#include "tests.h"
#include "udp_socket.hpp"

#include <vector>
#include <cstring>

using namespace core::network;

static std::uint16_t BoundPort(const UDPSocket& sock) {
    auto ep = sock.GetLocalEndpoint();
    return ep ? ep->port : 0;
}

bool UDPSocketTest_OpenClose() {
    UDPSocket sock;
    if (!sock.Open()) return false;
    if (!sock.IsOpen()) return false;
    if (sock.GetHandle() == kInvalidSocket) return false;
    sock.Close();
    return !sock.IsOpen();
}

bool UDPSocketTest_Bind() {
    UDPSocket sock;
    if (!sock.Open()) return false;
    if (!sock.Bind("127.0.0.1", 0)) return false;
    return BoundPort(sock) != 0;
}

bool UDPSocketTest_SendToReceiveFrom() {
    UDPSocket sender;
    UDPSocket receiver;
    sender.Open();
    receiver.Open();
    receiver.Bind("127.0.0.1", 0);

    std::vector<std::uint8_t> message = {0xDE, 0xAD, 0xBE, 0xEF};
    Endpoint dst{"127.0.0.1", BoundPort(receiver)};

    BytesTransferred sent = sender.SendTo(dst, message);
    if (sent != 4) return false;

    std::vector<std::uint8_t> buf(64);
    auto result = receiver.ReceiveFrom(buf);
    if (!result) return false;
    if (result->bytes_read != 4) return false;

    return std::memcmp(buf.data(), message.data(), 4) == 0;
}

bool UDPSocketTest_Loopback_SenderInfo() {
    UDPSocket sender;
    UDPSocket receiver;
    sender.Open();
    sender.Bind("127.0.0.1", 0);
    receiver.Open();
    receiver.Bind("127.0.0.1", 0);

    std::vector<std::uint8_t> message = {0x01};
    sender.SendTo({"127.0.0.1", BoundPort(receiver)}, message);

    std::vector<std::uint8_t> buf(64);
    auto result = receiver.ReceiveFrom(buf);
    if (!result) return false;

    return result->sender.ip == "127.0.0.1"
        && result->sender.port == BoundPort(sender);
}

bool UDPSocketTest_Loopback_1KB() {
    UDPSocket sender;
    UDPSocket receiver;
    sender.Open();
    receiver.Open();
    receiver.Bind("127.0.0.1", 0);

    std::vector<std::uint8_t> message(1024);
    for (std::size_t i = 0; i < message.size(); ++i) {
        message[i] = static_cast<std::uint8_t>(i & 0xFF);
    }

    Endpoint dst{"127.0.0.1", BoundPort(receiver)};
    if (sender.SendTo(dst, message) != 1024) return false;

    std::vector<std::uint8_t> buf(2048);
    auto result = receiver.ReceiveFrom(buf);
    if (!result) return false;
    if (result->bytes_read != 1024) return false;

    return std::memcmp(buf.data(), message.data(), 1024) == 0;
}

bool UDPSocketTest_ExternalDNSQuery() {
    UDPSocket sock;
    if (!sock.Open()) return false;
    if (!sock.Bind("0.0.0.0", 0)) return false;

    // Header: ID=0x1234, flags=0x0100 (standard query, recursion desired)
    // QDCOUNT=1, ANCOUNT=0, NSCOUNT=0, ARCOUNT=0
    // Question: example.com, type A (1), class IN (1)
    std::vector<std::uint8_t> dns_query = {
        0x12, 0x34,  // Transaction ID
        0x01, 0x00,  // Flags: standard query, recursion desired
        0x00, 0x01,  // Questions: 1
        0x00, 0x00,  // Answer RRs: 0
        0x00, 0x00,  // Authority RRs: 0
        0x00, 0x00,  // Additional RRs: 0
        // Query: example.com
        0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
        0x03, 'c', 'o', 'm',
        0x00,        // Root label
        0x00, 0x01,  // Type: A
        0x00, 0x01   // Class: IN
    };

    Endpoint dns_server{"8.8.8.8", 53};
    BytesTransferred sent = sock.SendTo(dns_server, dns_query);
    if (sent != static_cast<BytesTransferred>(dns_query.size())) return false;

    std::vector<std::uint8_t> buf(512);
    auto result = sock.ReceiveFrom(buf);
    if (!result) return false;

    // Verify: response has same transaction ID and is at least a header (12 bytes)
    if (result->bytes_read < 12) return false;
    if (buf[0] != 0x12 || buf[1] != 0x34) return false;

    // Verify: QR bit is set (response, not query)
    return (buf[2] & 0x80) != 0;
}