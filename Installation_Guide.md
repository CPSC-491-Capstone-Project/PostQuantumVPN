# Appendix IV: Installation Guide

> **Platform:** Linux is the only fully supported platform. macOS and Windows stubs exist in the codebase but are not functional.

---

## Prerequisites

Ensure the following are installed before building:

| Requirement | Minimum Version | Notes |
|-------------|-----------------|-------|
| `g++` or `clang++` | C++23 support | `g++ --version` to verify |
| OpenSSL | >= 3.5 | Must include ML-KEM EVP support |
| `cmake` | Any recent version | Required to build the bundled BLAKE3 library |
| `make` | GNU Make | Standard on most Linux distributions |
| Root / `sudo` | — | Required at runtime for TUN device creation |

### Installing OpenSSL 3.5

OpenSSL 3.5 introduced native ML-KEM support in the EVP API. Most distributions do not yet ship it by default.

**Check your current version:**
```bash
openssl version
```

**Arch Linux:**
```bash
sudo pacman -S openssl
```

**Ubuntu / Debian (build from source if version is < 3.5):**
```bash
# Download and build OpenSSL 3.5
wget https://github.com/openssl/openssl/releases/download/openssl-3.5.0/openssl-3.5.0.tar.gz
tar -xzf openssl-3.5.0.tar.gz
cd openssl-3.5.0
./Configure --prefix=/usr/local/openssl-3.5 --openssldir=/usr/local/openssl-3.5
make -j$(nproc)
sudo make install

# Point the build system to the custom prefix
export OPENSSL_PREFIX=/usr/local/openssl-3.5
```

If you installed OpenSSL to a non-default location, set `OPENSSL_PREFIX` before running any `make` commands:
```bash
export OPENSSL_PREFIX=/path/to/openssl-3.5
```

---

## Obtaining the Source

```bash
git clone <repository-url>
cd PostQuantumVPN
```

---

## Building the Client

The client binary (`PQ_VPN_Client`) is placed in `bin/` after a successful build.

```bash
make client
```

This will automatically build the bundled BLAKE3 library and all core modules before linking the client. To build with verbose output:

```bash
make client V=high
```

---

## Building the Server

The server binary (`PQ_VPN_Server`) is placed in `bin/` after a successful build.

```bash
make server
```

Like the client, this compiles the bundled libraries and core modules as needed. To build both the client and server in sequence:

```bash
make client server
```

---

## Cleaning Build Artifacts

```bash
make clean        # Remove obj/ and bin/
make clean-all    # Also remove bundled library build artifacts
```

---

## Test Suite

The project includes a test runner (`test_runner`) that exercises cryptographic primitives, networking components, and handshake logic in a single unity build.

**Build the test binary:**
```bash
make test
```

**Build and run all tests:**
```bash
make run-test
```

**Run a filtered subset of tests** using the `FILTER` variable:
```bash
make run-test FILTER="X25519"    # Run X25519 ECDH tests only
make run-test FILTER="ML-KEM"    # Run post-quantum KEM tests only
make run-test FILTER="Session"   # Run session encryption tests only
```

`FILTER` is a **case-sensitive substring match** against the full test name. Any test whose name contains the filter string will run. For example, `FILTER="KDF"` also matches HKDF tests since "HKDF" contains "KDF", and `FILTER="Session"` matches `SessionManager`, `SessionLifecycle`, and all `Session:` tests. Some useful prefixes: `Logger`, `Random`, `ML-KEM`, `ChaCha20`, `SipHash`, `HKDF`, `X25519`, `UDPSocket`, `IPv4`, `BLAKE3`, `EventPoller`, `TAI64N`, `MixHash`, `EaH`, `DaH`, `Session`, `HandshakeTimer`, `DeriveSessionKeys`, `KeyConfig`.

The test runner prints a pass/fail result for each case and exits with a non-zero code if any test fails.
