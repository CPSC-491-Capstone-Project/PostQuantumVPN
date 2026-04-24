#pragma once
#include <cstdint>
#include <optional>
#include <string>

namespace server {

inline constexpr const char* kServerConfigFile = "server.conf";

struct ServerConfig {
    std::string   bind_ip = "0.0.0.0";
    std::uint16_t port    = 51820;
};

class ServerConfigParser {
public:
    explicit ServerConfigParser(const char* path) : path_{path} {}
    [[nodiscard]] std::optional<ServerConfig> Parse();
private:
    const char* path_;
};

} // namespace server
