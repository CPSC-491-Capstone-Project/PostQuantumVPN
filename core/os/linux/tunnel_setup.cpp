#include "tunnel_setup.hpp"
#include "logger.hpp"

#include <arpa/inet.h>
#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <linux/fib_rules.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <net/if.h>
#include <string>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>
#include <vector>

using core::utils::Logger;

namespace core::network {
namespace {

// ── File helpers ─────────────────────────────────────────────────────────────

static bool WriteFile(const char* path, const char* value) {
    int fd = ::open(path, O_WRONLY);
    if (fd < 0) return false;
    std::size_t len = ::strlen(value);
    bool ok = ::write(fd, value, len) == static_cast<ssize_t>(len);
    ::close(fd);
    return ok;
}

// Append "id name\n" to rt_tables if the name is not already present.
static void EnsureRoutingTable(int id, const char* name) {
    int fd = ::open("/etc/iproute2/rt_tables", O_RDONLY);
    if (fd < 0) return;
    char buf[4096]{};
    ssize_t n = ::read(fd, buf, sizeof(buf) - 1);
    ::close(fd);
    if (n > 0 && ::strstr(buf, name)) return;

    fd = ::open("/etc/iproute2/rt_tables", O_WRONLY | O_APPEND);
    if (fd < 0) return;
    std::string entry = std::to_string(id) + " " + name + "\n";
    [[maybe_unused]] auto w = ::write(fd, entry.c_str(), entry.size());
    ::close(fd);
}

// ── Netlink helpers ───────────────────────────────────────────────────────────

static void NlAddAttr(struct nlmsghdr* nlh, uint16_t type,
                      const void* data, uint16_t len) {
    auto* rta = reinterpret_cast<struct rtattr*>(
        reinterpret_cast<uint8_t*>(nlh) + NLMSG_ALIGN(nlh->nlmsg_len));
    rta->rta_type = type;
    rta->rta_len  = static_cast<uint16_t>(RTA_LENGTH(len));
    if (data) ::memcpy(RTA_DATA(rta), data, len);
    nlh->nlmsg_len = static_cast<uint32_t>(
        NLMSG_ALIGN(nlh->nlmsg_len) + RTA_ALIGN(rta->rta_len));
}

// Send a netlink request and wait for ACK. Returns 0 on success, errno on error.
static int NlTransact(struct nlmsghdr* nlh) {
    int fd = ::socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);
    if (fd < 0) return errno;

    struct sockaddr_nl sa{};
    sa.nl_family = AF_NETLINK;
    if (::bind(fd, reinterpret_cast<struct sockaddr*>(&sa), sizeof(sa)) < 0) {
        int e = errno; ::close(fd); return e;
    }

    nlh->nlmsg_seq    = 1;
    nlh->nlmsg_pid    = 0;
    nlh->nlmsg_flags |= NLM_F_ACK;

    if (::send(fd, nlh, nlh->nlmsg_len, 0) < 0) {
        int e = errno; ::close(fd); return e;
    }

    char buf[8192];
    int result = 0;
    bool done = false;
    while (!done) {
        ssize_t n = ::recv(fd, buf, sizeof(buf), 0);
        if (n < 0) { result = errno; break; }
        uint32_t rem = static_cast<uint32_t>(n);
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wsign-conversion"
        for (auto* h = reinterpret_cast<struct nlmsghdr*>(buf);
             NLMSG_OK(h, rem);
             h = NLMSG_NEXT(h, rem))
        {
#pragma GCC diagnostic pop
            if (h->nlmsg_type == NLMSG_ERROR) {
                auto* err = static_cast<struct nlmsgerr*>(NLMSG_DATA(h));
                result = err->error < 0 ? -err->error : 0;
                done = true;
                break;
            }
            if (h->nlmsg_type == NLMSG_DONE) { done = true; break; }
        }
    }

    ::close(fd);
    return result;
}

// ── Route management ─────────────────────────────────────────────────────────

// Add a 0.0.0.0/0 route via oif in the given table; replaces any existing entry.
static bool AddDefaultRoute(int table_id, int oif) {
    struct { struct nlmsghdr nlh; struct rtmsg rtm; char attrs[128]; } req{};

    req.nlh.nlmsg_len   = NLMSG_LENGTH(sizeof(req.rtm));
    req.nlh.nlmsg_type  = RTM_NEWROUTE;
    req.nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_CREATE | NLM_F_REPLACE;

    req.rtm.rtm_family   = AF_INET;
    req.rtm.rtm_dst_len  = 0;
    req.rtm.rtm_table    = table_id < 256 ? static_cast<uint8_t>(table_id) : static_cast<uint8_t>(RT_TABLE_UNSPEC);
    req.rtm.rtm_protocol = RTPROT_STATIC;
    req.rtm.rtm_scope    = RT_SCOPE_LINK;
    req.rtm.rtm_type     = RTN_UNICAST;

    if (table_id >= 256) {
        auto t = static_cast<uint32_t>(table_id);
        NlAddAttr(&req.nlh, RTA_TABLE, &t, sizeof(t));
    }
    NlAddAttr(&req.nlh, RTA_OIF, &oif, sizeof(oif));

    return NlTransact(&req.nlh) == 0;
}

static void DeleteDefaultRoute(int table_id) {
    struct { struct nlmsghdr nlh; struct rtmsg rtm; char attrs[128]; } req{};

    req.nlh.nlmsg_len   = NLMSG_LENGTH(sizeof(req.rtm));
    req.nlh.nlmsg_type  = RTM_DELROUTE;
    req.nlh.nlmsg_flags = NLM_F_REQUEST;

    req.rtm.rtm_family  = AF_INET;
    req.rtm.rtm_dst_len = 0;
    req.rtm.rtm_table   = table_id < 256 ? static_cast<uint8_t>(table_id) : static_cast<uint8_t>(RT_TABLE_UNSPEC);

    if (table_id >= 256) {
        auto t = static_cast<uint32_t>(table_id);
        NlAddAttr(&req.nlh, RTA_TABLE, &t, sizeof(t));
    }
    (void)NlTransact(&req.nlh);
}

// ── Rule management ──────────────────────────────────────────────────────────

// fwmark == 0 means no fwmark match (catch-all rule).
static bool AddRule(uint32_t priority, uint32_t fwmark, uint32_t table_id) {
    struct { struct nlmsghdr nlh; struct fib_rule_hdr frh; char attrs[256]; } req{};

    req.nlh.nlmsg_len   = NLMSG_LENGTH(sizeof(req.frh));
    req.nlh.nlmsg_type  = RTM_NEWRULE;
    req.nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_CREATE | NLM_F_REPLACE;

    req.frh.family = AF_INET;
    req.frh.table  = table_id < 256 ? static_cast<uint8_t>(table_id) : static_cast<uint8_t>(RT_TABLE_UNSPEC);
    req.frh.action = FR_ACT_TO_TBL;

    NlAddAttr(&req.nlh, FRA_PRIORITY, &priority,  sizeof(priority));
    if (fwmark != 0)
        NlAddAttr(&req.nlh, FRA_FWMARK, &fwmark, sizeof(fwmark));
    if (table_id >= 256)
        NlAddAttr(&req.nlh, FRA_TABLE, &table_id, sizeof(table_id));

    return NlTransact(&req.nlh) == 0;
}

static void DeleteRule(uint32_t priority, uint32_t fwmark, uint32_t table_id) {
    struct { struct nlmsghdr nlh; struct fib_rule_hdr frh; char attrs[256]; } req{};

    req.nlh.nlmsg_len   = NLMSG_LENGTH(sizeof(req.frh));
    req.nlh.nlmsg_type  = RTM_DELRULE;
    req.nlh.nlmsg_flags = NLM_F_REQUEST;

    req.frh.family = AF_INET;
    req.frh.table  = table_id < 256 ? static_cast<uint8_t>(table_id) : static_cast<uint8_t>(RT_TABLE_UNSPEC);
    req.frh.action = FR_ACT_TO_TBL;

    NlAddAttr(&req.nlh, FRA_PRIORITY, &priority,  sizeof(priority));
    if (fwmark != 0)
        NlAddAttr(&req.nlh, FRA_FWMARK, &fwmark, sizeof(fwmark));
    if (table_id >= 256)
        NlAddAttr(&req.nlh, FRA_TABLE, &table_id, sizeof(table_id));

    (void)NlTransact(&req.nlh);
}

// ── Interface management ─────────────────────────────────────────────────────

static void SetIfaceDown(std::string_view ifname) {
    int fd = ::socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) return;
    struct ifreq ifr{};
    ::strncpy(ifr.ifr_name, ifname.data(), IFNAMSIZ - 1);
    if (::ioctl(fd, SIOCGIFFLAGS, &ifr) == 0) {
        ifr.ifr_flags = static_cast<short>(static_cast<int>(ifr.ifr_flags) & ~IFF_UP);
        (void)::ioctl(fd, SIOCSIFFLAGS, &ifr);
    }
    ::close(fd);
}

static void DeleteIface(std::string_view ifname) {
    unsigned idx = ::if_nametoindex(ifname.data());
    if (idx == 0) return;

    struct { struct nlmsghdr nlh; struct ifinfomsg ifi; } req{};
    req.nlh.nlmsg_len   = NLMSG_LENGTH(sizeof(req.ifi));
    req.nlh.nlmsg_type  = RTM_DELLINK;
    req.nlh.nlmsg_flags = NLM_F_REQUEST;
    req.ifi.ifi_index   = static_cast<int>(idx);

    (void)NlTransact(&req.nlh);
}

// ── Outbound interface detection ─────────────────────────────────────────────

static std::string DetectOutboundInterface() {
    struct { struct nlmsghdr nlh; struct rtmsg rtm; char attrs[128]; } req{};

    req.nlh.nlmsg_len   = NLMSG_LENGTH(sizeof(req.rtm));
    req.nlh.nlmsg_type  = RTM_GETROUTE;
    req.nlh.nlmsg_flags = NLM_F_REQUEST;
    req.rtm.rtm_family  = AF_INET;
    req.rtm.rtm_dst_len = 32;

    uint32_t dst = ::inet_addr("8.8.8.8");
    NlAddAttr(&req.nlh, RTA_DST, &dst, sizeof(dst));

    int fd = ::socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);
    if (fd < 0) return {};

    struct sockaddr_nl sa{};
    sa.nl_family = AF_NETLINK;
    ::bind(fd, reinterpret_cast<struct sockaddr*>(&sa), sizeof(sa));

    req.nlh.nlmsg_seq = 1;
    req.nlh.nlmsg_pid = 0;
    ::send(fd, &req, req.nlh.nlmsg_len, 0);

    char buf[8192];
    std::string result;
    bool done = false;
    while (!done) {
        ssize_t n = ::recv(fd, buf, sizeof(buf), 0);
        if (n < 0) break;
        uint32_t rem = static_cast<uint32_t>(n);
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wsign-conversion"
        for (auto* h = reinterpret_cast<struct nlmsghdr*>(buf);
             NLMSG_OK(h, rem);
             h = NLMSG_NEXT(h, rem))
        {
#pragma GCC diagnostic pop
            if (h->nlmsg_type == NLMSG_ERROR || h->nlmsg_type == NLMSG_DONE) {
                done = true; break;
            }
            if (h->nlmsg_type != RTM_NEWROUTE) continue;

            auto* rtm   = static_cast<struct rtmsg*>(NLMSG_DATA(h));
            int rta_rem = static_cast<int>(h->nlmsg_len - NLMSG_SPACE(sizeof(*rtm)));

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wsign-conversion"
            for (auto* rta = RTM_RTA(rtm);
                 RTA_OK(rta, rta_rem);
                 rta = RTA_NEXT(rta, rta_rem))
            {
#pragma GCC diagnostic pop
                if (rta->rta_type == RTA_OIF) {
                    int oif = *static_cast<const int*>(RTA_DATA(rta));
                    char name[IF_NAMESIZE]{};
                    if (::if_indextoname(static_cast<unsigned>(oif), name))
                        result = name;
                    done = true;
                    break;
                }
            }
        }
    }

    ::close(fd);
    return result;
}

// ── Firewall rules ───────────────────────────────────────────────────────────
// fork + execv: no shell, no console output.
// Used only for iptables/ip6tables which have no clean in-kernel C API.

static bool FindBinary(const char* name, std::string& out) {
    for (const char* prefix : { "/sbin/", "/usr/sbin/", "/usr/bin/" }) {
        std::string path = std::string(prefix) + name;
        if (::access(path.c_str(), X_OK) == 0) { out = path; return true; }
    }
    return false;
}

static bool ExecFirewall(const char* prog, std::vector<std::string> args) {
    std::string binary;
    if (!FindBinary(prog, binary)) return false;

    // Build argv before fork so the child never allocates.
    std::vector<const char*> argv;
    argv.reserve(args.size() + 2);
    argv.push_back(binary.c_str());
    for (const auto& a : args) argv.push_back(a.c_str());
    argv.push_back(nullptr);

    pid_t pid = ::fork();
    if (pid < 0) return false;

    if (pid == 0) {
        int null_fd = ::open("/dev/null", O_WRONLY);
        if (null_fd >= 0) {
            ::dup2(null_fd, STDOUT_FILENO);
            ::dup2(null_fd, STDERR_FILENO);
            ::close(null_fd);
        }
        ::execv(binary.c_str(), const_cast<char* const*>(argv.data()));
        ::_exit(1);
    }

    int status;
    ::waitpid(pid, &status, 0);
    return WIFEXITED(status) && WEXITSTATUS(status) == 0;
}

} // namespace

// ── Public API ───────────────────────────────────────────────────────────────

bool ConfigureClientRouting(std::string_view ifname, uint32_t fwmark, int routing_table) {
    const std::string iface(ifname);

    EnsureRoutingTable(routing_table, "vpn");

    int oif = static_cast<int>(::if_nametoindex(iface.c_str()));
    if (oif == 0) {
        Logger::Error("TunnelSetup: Interface not found: " + iface);
        return false;
    }

    if (!AddDefaultRoute(routing_table, oif)) {
        Logger::Error("TunnelSetup: Failed to add default route in table " +
                      std::to_string(routing_table));
        return false;
    }

    // Rule A (priority 50): fwmark → main table — VPN socket bypasses tunnel
    DeleteRule(50, fwmark, RT_TABLE_MAIN);
    if (!AddRule(50, fwmark, RT_TABLE_MAIN)) {
        Logger::Error("TunnelSetup: Failed to add fwmark bypass rule");
        return false;
    }

    // Rule B (priority 100): all other traffic → VPN table → tun
    DeleteRule(100, 0, static_cast<uint32_t>(routing_table));
    if (!AddRule(100, 0, static_cast<uint32_t>(routing_table))) {
        Logger::Error("TunnelSetup: Failed to add VPN routing rule");
        return false;
    }

    // Block IPv6 to prevent leaks (VPN tunnels IPv4 only)
    (void)ExecFirewall("ip6tables", {"-A", "OUTPUT",  "-j", "DROP"});
    (void)ExecFirewall("ip6tables", {"-A", "FORWARD", "-j", "DROP"});

    Logger::Info("TunnelSetup: Client routing configured — firewall mark " +
                 std::to_string(fwmark) + " bypasses tunnel");
    return true;
}

void RemoveClientRouting(std::string_view ifname, uint32_t fwmark, int routing_table) {
    DeleteRule(50,  fwmark, RT_TABLE_MAIN);
    DeleteRule(100, 0,      static_cast<uint32_t>(routing_table));
    DeleteDefaultRoute(routing_table);

    (void)ExecFirewall("ip6tables", {"-D", "OUTPUT",  "-j", "DROP"});
    (void)ExecFirewall("ip6tables", {"-D", "FORWARD", "-j", "DROP"});

    SetIfaceDown(ifname);
    DeleteIface(ifname);

    Logger::Info("TunnelSetup: Client routing removed");
}

bool ConfigureServerNAT(std::string_view ifname, std::string_view vpn_subnet) {
    (void)ifname; // ifname is used on teardown; setup only needs the subnet and outbound iface
    if (!WriteFile("/proc/sys/net/ipv4/ip_forward", "1")) {
        Logger::Error("TunnelSetup: Failed to enable IP forwarding");
        return false;
    }

    const std::string outbound = DetectOutboundInterface();
    if (outbound.empty()) {
        Logger::Error("TunnelSetup: Could not detect outbound interface");
        return false;
    }
    Logger::Info("TunnelSetup: Outbound interface: " + outbound);

    const std::string subnet(vpn_subnet);

    if (!ExecFirewall("iptables", {"-t", "nat", "-A", "POSTROUTING",
                                   "-s", subnet, "-o", outbound, "-j", "MASQUERADE"})) {
        Logger::Error("TunnelSetup: Failed to add NAT masquerade rule");
        return false;
    }

    (void)ExecFirewall("iptables", {"-A", "FORWARD",
                                    "-s", subnet, "-o", outbound, "-j", "ACCEPT"});
    (void)ExecFirewall("iptables", {"-A", "FORWARD",
                                    "-d", subnet, "-i", outbound,
                                    "-m", "state", "--state", "RELATED,ESTABLISHED",
                                    "-j", "ACCEPT"});

    Logger::Info("TunnelSetup: Server NAT configured — " + subnet + " → " + outbound);
    return true;
}

void RemoveServerNAT(std::string_view ifname, std::string_view vpn_subnet) {
    const std::string subnet(vpn_subnet);
    const std::string outbound = DetectOutboundInterface();

    if (!outbound.empty()) {
        (void)ExecFirewall("iptables", {"-t", "nat", "-D", "POSTROUTING",
                                        "-s", subnet, "-o", outbound, "-j", "MASQUERADE"});
        (void)ExecFirewall("iptables", {"-D", "FORWARD",
                                        "-s", subnet, "-o", outbound, "-j", "ACCEPT"});
        (void)ExecFirewall("iptables", {"-D", "FORWARD",
                                        "-d", subnet, "-i", outbound,
                                        "-m", "state", "--state", "RELATED,ESTABLISHED",
                                        "-j", "ACCEPT"});
    } else {
        Logger::Warning("TunnelSetup: Could not detect outbound interface — skipping iptables cleanup");
    }

    SetIfaceDown(ifname);
    DeleteIface(ifname);

    (void)WriteFile("/proc/sys/net/ipv4/ip_forward", "0");

    Logger::Info("TunnelSetup: Server NAT removed");
}

} // namespace core::network
