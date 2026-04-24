#pragma once
#include <cstdint>
#include <optional>
#include <string>

namespace client {

inline constexpr const char* kClientConfigFile = "client.conf";

struct ClientConfig {
    std::string   server_ip   = "127.0.0.1";
    std::uint16_t server_port = 51820;
    std::string   tun_iface      = "tun0";
    std::string   tun_ip         = "10.8.0.2";
    std::uint32_t firewall_mark  = 51820;
    int           vpn_table      = 100;
};

class ClientConfigParser {
public:
    explicit ClientConfigParser(const char* path) : path_{path} {}
    [[nodiscard]] std::optional<ClientConfig> Parse();
private:
    const char* path_;
};

} // namespace client
