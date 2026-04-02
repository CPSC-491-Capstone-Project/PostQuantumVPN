# Post Quantum VPN (Quantum Edge)

> **CPSC 490/491 Capstone Project — CSU Fullerton, Spring 2026**
> **Team Dune** | Faculty Advisor: Kyoung Shin

## Overview

Quantum Edge is a post-quantum Virtual Private Network (VPN) built from the ground up to resist both classical and quantum cryptographic attacks. It is heavily based off of WireGuard. This project addresses the "harvest-now, decrypt-later" risk by integrating NIST-recommended post-quantum cryptographic (PQC) algorithms - specifically **ML-KEM** for key encapsulation.

The VPN uses a **hybrid key exchange** (Kyber + X25519) to ensure security against both quantum and classical adversaries, with **ChaCha20-Poly1305** for symmetric encryption, **BLAKE3** for hashing, and **HKDF** for key derivation.

## Project Goals

1. **Build foundational cryptographic primitives** resistant to both classical and quantum attacks
2. **Develop a client-server VPN** where traffic flows through an encrypted tunnel using PQC-derived keys
3. **Implement a secure handshake and session management** system with replay protection
4. **Benchmark performance** against WireGuard + Rosenpass to ensure competitive throughput and latency

## Current Project Status

The project was designed in CPSC 490 and is being implemented in CPSC 491. Below is the status of each major module:

| Module | Status | Jira Epic |
|---|---|---|
| Logging Module | ✅ Done | DG-136 |
| Protocol Module | 🔧 In Progress | DG-137 |
| Cryptography Module | ✅ Done | DG-138 |
| Tunnel Module | 🧪 Testing | DG-139 |
| Network Module | 🔧 In Progress | DG-140 |
| Client Application | 📋 To Do | DG-141 |
| Server Application | 📋 To Do | DG-142 |
| Handshake Module | 🔧 In Progress | DG-143 |
| Session Module | 📋 To Do | DG-144 |
| Configuration Module | 📋 To Do | DG-145 |
| WireGuard + Rosenpass Baseline | 📋 To Do | DG-146 |
| VPN Performance Testing | 📋 To Do | DG-147 |
| Optimize Application | 📋 To Do | DG-148 |

### Completed Subtasks

- Logger levels, event structure, and thread-safe singleton logger
- All cryptographic primitives: Kyber (ML-KEM), X25519, BLAKE3, HKDF, ChaCha20-Poly1305, SipHash
- Full test suites for all crypto modules
- TUN device detection, creation, and attachment
- UDP socket wrapper and EPOLL event loop
- Handshake helper functions: MixHash, MixKey, KDF1/2/3, EncryptAndHash, DecryptAndHash
- TAI64N timestamps for handshake replay protection

## Building the Project

```bash
make run-client   # Builds and runs the client
make run-server   # Builds and runs the server
make help         # Outputs all available make commands
```

## Tests

### Writing Tests
1. Create a `.cpp` file for the module you want to test in `tests/`
2. Add your test code to the newly created file
3. Declare the function in `tests/tests.h`
4. Add `Run(TestFunction);` in `tests/test_runner.cpp`

See the sample tests included for reference.

### Running Tests
```bash
make test       # Builds all tests
make run-test   # Builds and runs all tests
```

## Project Links

- **Confluence (Project Report):** [CPSC 491 Project Report](https://dune-group15.atlassian.net/wiki/spaces/settings/pages/43909142/CPSC+491+Project+Report)
- **Jira Board:** [https://dune-group15.atlassian.net](https://dune-group15.atlassian.net)

## Tech Stack

- **Language:** C++
- **Build System:** Make
- **Cryptography:** CRYSTALS-Kyber (ML-KEM), X25519, ChaCha20-Poly1305, BLAKE3, HKDF, SipHash
- **Networking:** Linux TUN device, non-blocking UDP sockets, EPOLL
- **Project Management:** Jira (Scrum), Confluence, GitHub

## Authors

- **Chris Manlove** — ChrisManlove@csu.fullerton.edu
- **Cameron Rosenthal** — crosenthal@csu.fullerton.edu
- **Hunter Tran** — huntertran@csu.fullerton.edu
- **Quan Truong** — hungquantruong@csu.fullerton.edu