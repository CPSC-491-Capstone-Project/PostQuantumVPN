#ifndef _PQVPN_SERVER_SERVER_HPP_
#define _PQVPN_SERVER_SERVER_HPP_

#include "udp_socket.hpp"
#include "event_poller.hpp"
#include "handshake_constants.hpp"

namespace server {

    class Server {
    public:
        Server() = default;
        ~Server();

        Server(const Server&) = delete;
        Server& operator=(const Server&) = delete;
        Server(Server&&) = delete;
        Server& operator=(Server&&) = delete;

        // Configuration functions
        Server& SetBindAddress(std::string_view ip);
        

    };

} // namespace server

#endif // _PQVPN_SERVER_SERVER_HPP_