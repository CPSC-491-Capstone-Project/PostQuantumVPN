#include "client_config.hpp"
#include "logger.hpp"

#include <fstream>
#include <string>

namespace client {

using core::utils::Logger;

static bool WriteDefaults(const char* path, const ClientConfig& cfg) {
    std::ofstream f{path};
    if (!f) return false;
    f << "# PostQuantumVPN Client Configuration\n\n"
      << "server_ip     = " << cfg.server_ip     << "\n"
      << "server_port   = " << cfg.server_port   << "\n"
      << "tun_iface     = " << cfg.tun_iface     << "\n"
      << "tun_ip        = " << cfg.tun_ip        << "\n"
      << "firewall_mark = " << cfg.firewall_mark << "\n"
      << "vpn_table     = " << cfg.vpn_table     << "\n";
    return f.good();
}

static bool ParseFile(const char* path, ClientConfig& out) {
    std::ifstream f{path};
    if (!f) return false;

    std::string line;
    while (std::getline(f, line)) {
        auto s = line.find_first_not_of(" \t\r");
        if (s == std::string::npos || line[s] == '#') continue;
        line = line.substr(s);

        auto eq = line.find('=');
        if (eq == std::string::npos) continue;

        std::string key = line.substr(0, eq);
        if (auto e = key.find_last_not_of(" \t"); e != std::string::npos)
            key = key.substr(0, e + 1);

        std::string val = line.substr(eq + 1);
        if (auto vs = val.find_first_not_of(" \t"); vs != std::string::npos)
            val = val.substr(vs);
        if (auto ve = val.find_last_not_of(" \t\r\n"); ve != std::string::npos)
            val = val.substr(0, ve + 1);

        if (key == "server_ip") {
            out.server_ip = val;
        } else if (key == "server_port") {
            try { out.server_port = static_cast<std::uint16_t>(std::stoi(val)); }
            catch (...) { Logger::Warning("client_config: invalid server_port, using default"); }
        } else if (key == "tun_iface") {
            out.tun_iface = val;
        } else if (key == "tun_ip") {
            out.tun_ip = val;
        } else if (key == "firewall_mark") {
            try { out.firewall_mark = static_cast<std::uint32_t>(std::stoul(val)); }
            catch (...) { Logger::Warning("client_config: invalid firewall_mark, using default"); }
        } else if (key == "vpn_table") {
            try { out.vpn_table = std::stoi(val); }
            catch (...) { Logger::Warning("client_config: invalid vpn_table, using default"); }
        }
    }
    return true;
}

std::optional<ClientConfig> ClientConfigParser::Parse() {
    if (std::ifstream probe{path_}; !probe.good()) {
        ClientConfig defaults{};
        if (!WriteDefaults(path_, defaults)) {
            Logger::Error("client_config: Failed to create " + std::string{path_});
            return std::nullopt;
        }
        Logger::Info("client_config: Created " + std::string{path_} + " with defaults");
        return defaults;
    }

    ClientConfig cfg{};
    if (!ParseFile(path_, cfg)) {
        Logger::Error("client_config: Failed to parse " + std::string{path_});
        return std::nullopt;
    }
    Logger::Info("client_config: Loaded " + std::string{path_});
    return cfg;
}

} // namespace client
