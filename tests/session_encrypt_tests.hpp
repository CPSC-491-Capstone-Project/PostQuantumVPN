#ifndef _PQVPN_TESTS_SESSION_ENCRYPT_TESTS_HPP_
#define _PQVPN_TESTS_SESSION_ENCRYPT_TESTS_HPP_

#include "test_utils.hpp"
#include "session.hpp"
#include "session_manager.hpp"
#include "ipv4.hpp"

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>
#include <functional>
#include <memory>
#include <string>
#include <thread>
#include <vector>

using core::session::Session;
using core::session::SessionManager;
using core::session::SessionSecrets;
using core::session::ConstByteSpan;

namespace cc = core::cryptography::chacha20_poly1305;

// ============================================================================
// Helpers (SeTest_ prefix to avoid name collisions across test files)
// ============================================================================

static cc::Key SeTest_MakeKey(std::uint8_t pattern) {
    cc::Key k;
    k.fill(pattern);
    return k;
}

static std::unique_ptr<Session> SeTest_MakeSession(
    const cc::Key& send_key, const cc::Key& recv_key,
    std::uint32_t sender_index = 1000, std::uint32_t receiver_index = 2000) {
    auto s = std::make_unique<Session>();
    s->send_key       = send_key;
    s->recv_key       = recv_key;
    s->sender_index   = sender_index;
    s->receiver_index = receiver_index;
    s->created        = std::chrono::system_clock::now();
    return s;
}

static core::network::Endpoint SeTest_MakeEndpoint() {
    return core::network::Endpoint{core::network::IPv4(127, 0, 0, 1), 51820};
}

// Matching session pair: client.send_key == server.recv_key and vice versa.
struct SeTest_Pair {
    std::unique_ptr<Session> client;
    std::unique_ptr<Session> server;
};

static SeTest_Pair SeTest_MakePair(
    std::uint8_t client_send = 0xAA, std::uint8_t server_send = 0xBB,
    std::uint32_t client_idx = 1000,  std::uint32_t server_idx  = 2000) {
    auto cs = SeTest_MakeKey(client_send);
    auto ss = SeTest_MakeKey(server_send);
    SeTest_Pair p;
    p.client = SeTest_MakeSession(cs, ss, client_idx, server_idx);
    p.server = SeTest_MakeSession(ss, cs, server_idx, client_idx);
    return p;
}

// ============================================================================
// Stage 1: Seal produces a value
// ============================================================================

bool SessionSealTest_ProducesValue() {
    auto p = SeTest_MakePair();
    std::vector<std::uint8_t> pt = {0x01, 0x02, 0x03};
    return test_helper("1", std::to_string(p.client->Seal(ConstByteSpan{pt}).has_value()));
}

bool SessionSealTest_OutputLength() {
    auto p = SeTest_MakePair();
    std::vector<std::uint8_t> pt(100, 0xDE);
    auto result = p.client->Seal(ConstByteSpan{pt});
    if (!result) return test_helper("non-nullopt", "nullopt");
    // plaintext (100) + Poly1305 tag (16) = 116
    return test_helper(std::to_string(pt.size() + 16), std::to_string(result->size()));
}

bool SessionSealTest_CiphertextDiffersFromPlaintext() {
    auto p = SeTest_MakePair();
    std::vector<std::uint8_t> pt(32, 0xAB);
    auto result = p.client->Seal(ConstByteSpan{pt});
    if (!result) return test_helper("non-nullopt", "nullopt");
    bool differs = (std::memcmp(result->data(), pt.data(), pt.size()) != 0);
    return test_helper("1", std::to_string(differs));
}

bool SessionSealTest_EmptyPlaintext() {
    auto p = SeTest_MakePair();
    auto result = p.client->Seal(ConstByteSpan{});
    if (!result) return test_helper("non-nullopt", "nullopt");
    // Empty plaintext → tag only (16 bytes)
    return test_helper("16", std::to_string(result->size()));
}

bool SessionSealTest_CounterIncrementsPerCall() {
    auto p = SeTest_MakePair();
    std::vector<std::uint8_t> pt(8, 0x11);
    for (int i = 0; i < 5; ++i) {
        if (!p.client->Seal(ConstByteSpan{pt})) return test_helper("seal_" + std::to_string(i), "nullopt");
    }
    // After 5 seals, counter should be 5
    return test_helper("5", std::to_string(p.client->send_nonce.load()));
}

// ============================================================================
// Stage 2: Roundtrip — Seal then Open recovers plaintext
// ============================================================================

bool SessionRoundtrip_Basic() {
    auto p = SeTest_MakePair();
    std::vector<std::uint8_t> pt(64, 0xDE);
    auto sealed = p.client->Seal(ConstByteSpan{pt});
    if (!sealed) return test_helper("sealed", "nullopt");
    // Seal used counter 0 (send_nonce was 0 before fetch_add)
    auto dec = p.server->Open(0, ConstByteSpan{*sealed});
    if (!dec) return test_helper("decrypted", "nullopt");
    return test_helper("1", std::to_string(*dec == pt));
}

bool SessionRoundtrip_EmptyPlaintext() {
    auto p = SeTest_MakePair();
    auto sealed = p.client->Seal(ConstByteSpan{});
    if (!sealed) return test_helper("sealed", "nullopt");
    auto dec = p.server->Open(0, ConstByteSpan{*sealed});
    if (!dec) return test_helper("decrypted", "nullopt");
    return test_helper("1", std::to_string(dec->empty()));
}

bool SessionRoundtrip_LargePacket() {
    auto p = SeTest_MakePair();
    std::vector<std::uint8_t> pt(1400, 0xCC);
    auto sealed = p.client->Seal(ConstByteSpan{pt});
    if (!sealed) return test_helper("sealed", "nullopt");
    auto dec = p.server->Open(0, ConstByteSpan{*sealed});
    if (!dec) return test_helper("decrypted", "nullopt");
    return test_helper("1", std::to_string(*dec == pt));
}

// ============================================================================
// Stage 3: Multiple sequential messages all round-trip correctly
// ============================================================================

bool SessionRoundtrip_MultipleMessages() {
    auto p = SeTest_MakePair();
    constexpr int kCount = 50;
    for (int i = 0; i < kCount; ++i) {
        std::vector<std::uint8_t> pt(32, static_cast<std::uint8_t>(i));
        auto sealed = p.client->Seal(ConstByteSpan{pt});
        if (!sealed) return test_helper("seal_" + std::to_string(i), "nullopt");
        auto dec = p.server->Open(static_cast<std::uint64_t>(i), ConstByteSpan{*sealed});
        if (!dec)     return test_helper("open_" + std::to_string(i), "nullopt");
        if (*dec != pt) return test_helper("match_" + std::to_string(i), "mismatch");
    }
    return test_helper("1", "1");
}

bool SessionRoundtrip_OutOfOrderWithinWindow() {
    auto p = SeTest_MakePair();

    // Seal 5 packets (counters 0–4)
    std::array<std::vector<std::uint8_t>, 5> sealed;
    for (int i = 0; i < 5; ++i) {
        std::vector<std::uint8_t> pt(16, static_cast<std::uint8_t>(i));
        auto s = p.client->Seal(ConstByteSpan{pt});
        if (!s) return test_helper("seal_" + std::to_string(i), "nullopt");
        sealed[static_cast<std::size_t>(i)] = *s;
    }

    // Deliver out of order: 4, 2, 0, 1, 3
    const std::array<int, 5> order = {4, 2, 0, 1, 3};
    for (int idx : order) {
        std::vector<std::uint8_t> expected(16, static_cast<std::uint8_t>(idx));
        auto dec = p.server->Open(static_cast<std::uint64_t>(idx),
                                  ConstByteSpan{sealed[static_cast<std::size_t>(idx)]});
        if (!dec)       return test_helper("open_" + std::to_string(idx), "nullopt");
        if (*dec != expected) return test_helper("match_" + std::to_string(idx), "mismatch");
    }

    // Replay of index 2 must now be rejected
    auto replay = p.server->Open(2, ConstByteSpan{sealed[2]});
    return test_helper("1", std::to_string(!replay.has_value()));
}

// ============================================================================
// Rejection tests (each builds on the prior stage)
// ============================================================================

bool SessionOpen_RejectsReplay() {
    auto p = SeTest_MakePair();
    std::vector<std::uint8_t> pt(32, 0x99);
    auto sealed = p.client->Seal(ConstByteSpan{pt});
    if (!sealed) return test_helper("sealed", "nullopt");

    auto first = p.server->Open(0, ConstByteSpan{*sealed});
    if (!first) return test_helper("first open", "nullopt");

    auto second = p.server->Open(0, ConstByteSpan{*sealed});
    return test_helper("1", std::to_string(!second.has_value()));
}

bool SessionOpen_RejectsTamperedCiphertext() {
    auto p = SeTest_MakePair();
    std::vector<std::uint8_t> pt(32, 0x55);
    auto sealed = p.client->Seal(ConstByteSpan{pt});
    if (!sealed) return test_helper("sealed", "nullopt");

    (*sealed)[0] ^= 0xFF;  // flip first byte of ciphertext

    auto result = p.server->Open(0, ConstByteSpan{*sealed});
    return test_helper("1", std::to_string(!result.has_value()));
}

bool SessionOpen_RejectsTamperedTag() {
    auto p = SeTest_MakePair();
    std::vector<std::uint8_t> pt(32, 0x77);
    auto sealed = p.client->Seal(ConstByteSpan{pt});
    if (!sealed) return test_helper("sealed", "nullopt");

    // Flip last byte (in the tag)
    sealed->back() ^= 0xFF;

    auto result = p.server->Open(0, ConstByteSpan{*sealed});
    return test_helper("1", std::to_string(!result.has_value()));
}

bool SessionOpen_RejectsTooShort() {
    auto p = SeTest_MakePair();
    std::vector<std::uint8_t> short_buf(15, 0x00);  // < 16-byte tag
    auto result = p.server->Open(0, ConstByteSpan{short_buf});
    return test_helper("1", std::to_string(!result.has_value()));
}

bool SessionOpen_RejectsCounterAtLimit() {
    auto p = SeTest_MakePair();
    std::vector<std::uint8_t> fake(48, 0x00);
    auto result = p.server->Open(core::session::kRejectAfterMessages, ConstByteSpan{fake});
    return test_helper("1", std::to_string(!result.has_value()));
}

bool SessionOpen_RejectsCounterTooOld() {
    auto p = SeTest_MakePair();
    // Manually advance server's replay window to last_ = 3000
    p.server->replay_window.Accept(3000);
    // counter 952: 952 + 2048 = 3000 <= 3000 → outside window
    std::vector<std::uint8_t> fake(48, 0x00);
    auto result = p.server->Open(952, ConstByteSpan{fake});
    return test_helper("1", std::to_string(!result.has_value()));
}

bool SessionSeal_RejectsExhaustedCounter() {
    auto p = SeTest_MakePair();
    p.client->send_nonce.store(core::session::kRejectAfterMessages, std::memory_order_relaxed);
    std::vector<std::uint8_t> pt(32, 0xAA);
    auto result = p.client->Seal(ConstByteSpan{pt});
    return test_helper("1", std::to_string(!result.has_value()));
}

// ============================================================================
// Stage 4: Multiple independent client sessions (single-threaded)
// ============================================================================

bool SessionMultiClient_Independent() {
    constexpr std::size_t kNumClients = 8;
    constexpr std::size_t kPackets    = 10;

    for (std::size_t i = 0; i < kNumClients; ++i) {
        auto p = SeTest_MakePair(
            static_cast<std::uint8_t>(0x10 + i),
            static_cast<std::uint8_t>(0x20 + i),
            static_cast<std::uint32_t>(100 + i),
            static_cast<std::uint32_t>(200 + i));

        for (std::size_t j = 0; j < kPackets; ++j) {
            std::vector<std::uint8_t> pt(32, static_cast<std::uint8_t>(i * 10 + j));
            auto sealed = p.client->Seal(ConstByteSpan{pt});
            if (!sealed) return test_helper("seal_c" + std::to_string(i) + "_p" + std::to_string(j), "nullopt");
            auto dec = p.server->Open(j, ConstByteSpan{*sealed});
            if (!dec || *dec != pt) return test_helper("open_c" + std::to_string(i) + "_p" + std::to_string(j), "fail");
        }
    }
    return test_helper("1", "1");
}

// ============================================================================
// Stage 5: Multiple clients via SessionManager lookup (single-threaded)
// ============================================================================

bool SessionMultiClient_SessionManagerLookup() {
    constexpr std::size_t kNumClients = 6;

    SessionManager server_mgr;

    // Register one server session per client (server_idx[i] is the sender index
    // the server uses; it's what the client stores as its receiver_index)
    std::array<std::uint32_t, kNumClients> server_idx{};
    for (std::size_t i = 0; i < kNumClients; ++i) {
        server_idx[i] = static_cast<std::uint32_t>(1000 + i);
        SessionSecrets s;
        s.recv_key       = SeTest_MakeKey(static_cast<std::uint8_t>(0x10 + i));  // == client send
        s.send_key       = SeTest_MakeKey(static_cast<std::uint8_t>(0x50 + i));  // == client recv
        s.sender_index   = server_idx[i];
        s.receiver_index = static_cast<std::uint32_t>(2000 + i);
        s.is_initiator   = false;
        server_mgr.ActivateSession(s, SeTest_MakeEndpoint());
    }

    for (std::size_t i = 0; i < kNumClients; ++i) {
        auto client = SeTest_MakeSession(
            SeTest_MakeKey(static_cast<std::uint8_t>(0x10 + i)),
            SeTest_MakeKey(static_cast<std::uint8_t>(0x50 + i)),
            static_cast<std::uint32_t>(2000 + i),
            server_idx[i]);

        std::vector<std::uint8_t> pt(48, static_cast<std::uint8_t>(0xDE + i));
        auto sealed = client->Seal(ConstByteSpan{pt});
        if (!sealed) return test_helper("seal_" + std::to_string(i), "nullopt");

        // Server looks up by sender_index (same as client's receiver_index)
        Session* server = server_mgr.Lookup(server_idx[i]);
        if (!server) return test_helper("lookup_" + std::to_string(i), "nullptr");

        auto dec = server->Open(0, ConstByteSpan{*sealed});
        if (!dec || *dec != pt) return test_helper("open_" + std::to_string(i), "fail");
    }
    return test_helper("1", "1");
}

// ============================================================================
// Stage 6: Multi-threaded full round trip
//
// N client threads simultaneously exchange packets with a shared server
// SessionManager. Each thread handles one independent client↔server session
// pair, exercising:
//   - Concurrent SessionManager::Lookup reads
//   - Independent per-session counters and replay windows
//   - Bidirectional encrypted communication
//   - Payload integrity verification after decryption
// ============================================================================

bool SessionMultiClient_MultiThread_FullRoundTrip(std::function<void()> start_timer) {
    constexpr std::size_t kNumClients      = 5;
    constexpr std::size_t kPacketsPerDir   = 12;  // packets per direction per client

    SessionManager server_mgr;

    // Set up one server session per client.
    // server recv_key[i] == client send_key[i], server send_key[i] == client recv_key[i].
    std::array<std::uint32_t, kNumClients> server_idx{};
    for (std::size_t i = 0; i < kNumClients; ++i) {
        server_idx[i] = static_cast<std::uint32_t>(1000 + i);
        SessionSecrets s;
        s.recv_key       = SeTest_MakeKey(static_cast<std::uint8_t>(0x30 + i));
        s.send_key       = SeTest_MakeKey(static_cast<std::uint8_t>(0x60 + i));
        s.sender_index   = server_idx[i];
        s.receiver_index = static_cast<std::uint32_t>(2000 + i);
        s.is_initiator   = false;
        server_mgr.ActivateSession(s, SeTest_MakeEndpoint());
    }

    // Per-client sessions (send_key[i] == server's recv_key[i])
    std::array<std::unique_ptr<Session>, kNumClients> client_sessions;
    for (std::size_t i = 0; i < kNumClients; ++i) {
        client_sessions[i] = SeTest_MakeSession(
            SeTest_MakeKey(static_cast<std::uint8_t>(0x30 + i)),
            SeTest_MakeKey(static_cast<std::uint8_t>(0x60 + i)),
            static_cast<std::uint32_t>(2000 + i),
            server_idx[i]);
    }

    std::array<bool, kNumClients> results{};
    results.fill(true);

    start_timer();

    std::array<std::thread, kNumClients> threads;
    for (std::size_t i = 0; i < kNumClients; ++i) {
        threads[i] = std::thread([&, i]() {
            Session* client = client_sessions[i].get();

            // Look up this client's server session (concurrent reads from multiple threads)
            Session* server = server_mgr.Lookup(server_idx[i]);
            if (!server) { results[i] = false; return; }

            // ---- Client → Server ----
            for (std::size_t p = 0; p < kPacketsPerDir; ++p) {
                std::vector<std::uint8_t> pt(40,
                    static_cast<std::uint8_t>(i * 16 + p));

                auto sealed = client->Seal(ConstByteSpan{pt});
                if (!sealed) { results[i] = false; return; }

                // Counter p was used by Seal (send_nonce started at 0)
                auto dec = server->Open(static_cast<std::uint64_t>(p), ConstByteSpan{*sealed});
                if (!dec || *dec != pt) { results[i] = false; return; }
            }

            // ---- Server → Client ----
            for (std::size_t p = 0; p < kPacketsPerDir; ++p) {
                std::vector<std::uint8_t> reply(40,
                    static_cast<std::uint8_t>(0x80 + i * 16 + p));

                auto sealed = server->Seal(ConstByteSpan{reply});
                if (!sealed) { results[i] = false; return; }

                auto dec = client->Open(static_cast<std::uint64_t>(p), ConstByteSpan{*sealed});
                if (!dec || *dec != reply) { results[i] = false; return; }
            }
        });
    }

    for (auto& t : threads) t.join();

    bool all_ok = std::all_of(results.begin(), results.end(), [](bool b) { return b; });
    return test_helper("1", std::to_string(all_ok));
}

#endif // _PQVPN_TESTS_SESSION_ENCRYPT_TESTS_HPP_
