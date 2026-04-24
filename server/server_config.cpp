#include "server_config.hpp"
#include "logger.hpp"

#include <fstream>
#include <string>

namespace server {

using core::utils::Logger;

static bool WriteDefaults(const char* path, const ServerConfig& cfg) {
    std::ofstream f{path};
    if (!f) return false;
    f << "# PostQuantumVPN Server Configuration\n\n"
      << "bind_ip    = " << cfg.bind_ip    << "\n"
      << "port       = " << cfg.port       << "\n"
      << "tun_iface  = " << cfg.tun_iface  << "\n"
      << "vpn_subnet = " << cfg.vpn_subnet << "\n";
    return f.good();
}

static bool ParseFile(const char* path, ServerConfig& out) {
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

        if (key == "bind_ip") {
            out.bind_ip = val;
        } else if (key == "port") {
            try { out.port = static_cast<std::uint16_t>(std::stoi(val)); }
            catch (...) { Logger::Warning("server_config: invalid port, using default"); }
        } else if (key == "tun_iface") {
            out.tun_iface = val;
        } else if (key == "vpn_subnet") {
            out.vpn_subnet = val;
        }
    }
    return true;
}

std::optional<ServerConfig> ServerConfigParser::Parse() {
    if (std::ifstream probe{path_}; !probe.good()) {
        ServerConfig defaults{};
        if (!WriteDefaults(path_, defaults)) {
            Logger::Error("server_config: Failed to create " + std::string{path_});
            return std::nullopt;
        }
        Logger::Info("server_config: Created " + std::string{path_} + " with defaults");
        return defaults;
    }

    ServerConfig cfg{};
    if (!ParseFile(path_, cfg)) {
        Logger::Error("server_config: Failed to parse " + std::string{path_});
        return std::nullopt;
    }
    Logger::Info("server_config: Loaded " + std::string{path_});
    return cfg;
}

} // namespace server
