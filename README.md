# Post Quantum VPN (Quantum Edge)

> **CPSC 490/491 Capstone Project | CSU Fullerton, Spring 2026**
> **Team Dune** | Faculty Advisor: Kyoung Shin

## Team Members

| Name | Email |
|------|-------|
| Chris Manlove | ChrisManlove@csu.fullerton.edu |
| Cameron Rosenthal | crosenthal@csu.fullerton.edu |
| Hunter Tran | huntertran@csu.fullerton.edu |
| Quan Truong | hungquantruong@csu.fullerton.edu |

## Overview

Quantum Edge is a post-quantum Virtual Private Network (VPN) built from the ground up to resist both classical and quantum cryptographic attacks. It is heavily based on WireGuard and addresses the "harvest-now, decrypt-later" threat by integrating NIST-recommended post-quantum cryptographic (PQC) algorithms, specifically **ML-KEM-768** for key encapsulation.

The VPN uses a **hybrid key exchange** (ML-KEM + X25519) to ensure security against both quantum and classical adversaries, with **ChaCha20-Poly1305** for symmetric encryption, **BLAKE3** for hashing, and **HKDF** for key derivation.

## Project Goals

1. Build foundational cryptographic primitives resistant to both classical and quantum attacks
2. Develop a client-server VPN where traffic flows through an encrypted tunnel using PQC-derived keys
3. Implement a secure handshake and session management system with replay protection
4. Benchmark performance against WireGuard + Rosenpass to ensure competitive throughput and latency

---

## Prerequisites

- Linux (primary supported platform)
- `g++` or `clang++` with C++23 support
- OpenSSL >= 3.5 (with ML-KEM EVP support)
- `cmake` (for building bundled BLAKE3 library)
- Root/`sudo` access (required for TUN device creation)

To install OpenSSL 3.5 on Ubuntu if not already present:
```bash
# Check version
openssl version

# If < 3.5, build from source or use a PPA with OpenSSL 3.5
```

---

## Building

```bash
make help         # List all available make targets
make libs         # Build bundled libraries (BLAKE3)
make core         # Build core module
make client       # Build client binary only
make server       # Build server binary only
make test         # Build test binary only
```

All binaries are placed in `bin/`.

---

## How to Use

### Step 1: Start the server

```bash
make run-server
```

On first run, the server generates `server_keys.conf` and prints its public keys:

```
=== Public Keys (share these with peers) ===
x25519_public = <64 hex chars>
mlkem_ek = <2368 hex chars>
=============================================
```

On every subsequent run it reloads keys from `server_keys.conf`.

> **Keep `server_keys.conf` private.** Only `x25519_public` and `mlkem_ek` should be shared with clients.

### Step 2: Configure the client

The client reads `client.conf`. It needs the server's public keys and address:

```ini
server_x25519_public = <value from server output>
server_mlkem_ek      = <value from server output>
server_ip            = <server IP address>
server_port          = 51820
```

The client also needs its own keypair in `client_keys.conf` (same format as the server; generated on first run).

### Step 3: Start the client

```bash
make run-client
```

The client performs the hybrid handshake with the server and establishes an encrypted session. Traffic routed through the TUN interface is encrypted end-to-end.

### Key/config file format

```ini
# PostQuantumVPN Keys
x25519_private = <64 hex chars>   # 32-byte private key  (keep secret)
x25519_public  = <64 hex chars>   # 32-byte public key   (share with peers)
mlkem_dk       = <4800 hex chars> # 2400-byte decapsulation key (keep secret)
mlkem_ek       = <2368 hex chars> # 1184-byte encapsulation key (share with peers)
```

---

## Project Structure

```
PostQuantumVPN/
├── core/                   # Shared VPN infrastructure
│   ├── cryptography/       # Crypto primitives
│   ├── handshake/          # Noise-like hybrid handshake protocol
│   ├── session/            # Active session encryption & replay protection
│   ├── network/            # UDP sockets, TUN device, event polling
│   ├── os/                 # Platform-specific code (linux/, macos/, windows/)
│   ├── config/             # Keypair file parsing
│   └── utils/              # Logging, RNG, bit utils, secure memory, timestamps
├── client/                 # VPN client (main.cpp + client logic)
├── server/                 # VPN server (main.cpp + server logic)
├── tests/                  # Unity-build test suite (30 test modules)
├── libs/                   # Bundled BLAKE3 library (C, SIMD-optimized)
├── scripts/                # Helper scripts
├── Makefile
├── client.conf             # Client configuration
├── server.conf             # Server configuration
└── JIRA_TICKETS.jsonl      # Project backlog reference
```

### Component Details

#### `core/cryptography/`
All cryptographic primitives via the OpenSSL EVP API:

| Module | Algorithm | Purpose |
|--------|-----------|---------|
| `x25519` | X25519 | Classical Diffie-Hellman |
| `ml_kem` | ML-KEM-768 | Post-quantum key encapsulation |
| `chacha20_poly1305` | ChaCha20-Poly1305 | Symmetric AEAD encryption |
| `blake3` | BLAKE3 | Hash / PRF (bundled lib) |
| `hkdf` | HKDF | Key derivation |
| `siphash` | SipHash | MAC / fast hash |

#### `core/handshake/`
Implements a WireGuard/Noise-inspired hybrid handshake (IKpq):

- **Message Type 1 (Initiation):** Client sends ephemeral X25519 pubkey + ML-KEM ciphertext + encrypted timestamp
- **Message Type 2 (Response):** Server replies with its own ephemeral keys + derived session material
- **KDF chain:** `MixHash` / `MixKey` / `EncryptAndHash` / `DecryptAndHash` / `KDF1` / `KDF2` / `KDF3`
- **Cookie system:** MAC1/MAC2 fields for under-load protection

#### `core/session/`
Manages active encrypted sessions after handshake:

- `session`: ChaCha20-Poly1305 send/receive keys, atomic nonce counter
- `session_manager`: Session lifecycle (create, activate, retire)
- `replay_window`: Sliding-window anti-replay protection (2048 packets)

#### `core/network/`
Platform-agnostic networking:

- `udp_socket`: Non-blocking UDP socket wrapper
- `tun_device`: TUN virtual network interface
- `event_poller`: EPOLL-based I/O multiplexing (Linux)
- `ipv4`: IPv4 address and port types

#### `core/os/`
Platform-specific implementations isolated here. Currently: `linux/`, `macos/`, `windows/` stubs.

#### `core/utils/`
- `logger`: Configurable log levels
- `random`: Cryptographically secure RNG
- `secure_memory`: `secure_zero()` for wiping sensitive buffers
- `tai64n`: TAI64N timestamp (used in handshake initiation messages)
- `bit_utils`: Bit/byte conversion helpers

---

## Tests

The test suite uses a **unity build**: all test logic lives in `.hpp` headers compiled into a single `test_runner.cpp` translation unit.

```bash
make run-test                 # Build and run all tests
make run-test FILTER="X25519" # Run only tests whose name contains "X25519"
```

Available `FILTER` values:

| Filter | What it runs |
|--------|--------------|
| `Logger` | Logger + LogEvent tests |
| `Random` | RNG tests |
| `BitsToBytes` | Bit utils |
| `BytesToBits` | Bit utils |
| `Hex` | Hex encoding tests |
| `ML-KEM` | Post-quantum KEM tests |
| `ChaCha20` | AEAD encryption tests |
| `SipHash` | SipHash MAC tests |
| `HKDF` | Key derivation tests |
| `X25519` | Classical ECDH tests |
| `UDPSocket` | UDP socket tests |
| `IPv4` | IPv4 address tests |
| `BLAKE3` | BLAKE3 hash + XOF tests |
| `EventPoller` | Event poller tests |
| `TAI64N` | Timestamp tests |
| `MixHash` | Handshake MixHash tests |
| `KDF` | All KDF1 + KDF2 + KDF3 + HKDF |
| `EaH` | EncryptAndHash tests |
| `DaH` | DecryptAndHash tests |
| `Session` | Session encryption + lifecycle |

### Writing Tests

1. Create `tests/<module>_tests.hpp` with a header guard:
   ```cpp
   #ifndef _PQVPN_TESTS_<MODULE>_TESTS_HPP_
   #define _PQVPN_TESTS_<MODULE>_TESTS_HPP_

   #include "test_utils.hpp"
   #include "<module>.hpp"

   bool MyTest_SomeCase() {
       return test_helper("expected", actual);
   }

   #endif
   ```
2. `#include` it in `tests/test_runner.cpp` (keep list alphabetical).
3. Add `Run(MyTest_SomeCase, "My module: some case");` inside `main()`.

> Avoid `using namespace` at file scope in test headers; all headers share one translation unit.

---

## Tech Stack

| Layer | Technology |
|-------|------------|
| Language | C++23 |
| Build | GNU Make + g++/clang++ |
| Cryptography | ML-KEM-768, X25519, ChaCha20-Poly1305, BLAKE3, HKDF, SipHash |
| Networking | Linux TUN device, non-blocking UDP, EPOLL |
| Project Management | Jira (Scrum), Confluence, GitHub |

---

## Project Links

- **Confluence (Project Report):** [CPSC 491 Project Report](https://dune-group15.atlassian.net/wiki/spaces/settings/pages/43909142/CPSC+491+Project+Report)
- **Jira Board:** [https://dune-group15.atlassian.net](https://dune-group15.atlassian.net)
