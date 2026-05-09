# Appendix V: Usage Guide

> Both the client and server must be run as **root** (or with `sudo`) because they create a TUN virtual network interface, which requires `CAP_NET_ADMIN`.

---

## Step 1: Start the Server

From the repository root, run:

```bash
sudo ./bin/PQ_VPN_Server
```

Or use the make shortcut (also builds first):

```bash
sudo make run-server
```

### First Run — Key Generation

On first run, the server finds no `server_keys.conf` and automatically generates a fresh keypair:

- An **X25519** keypair (classical Diffie-Hellman)
- An **ML-KEM-768** keypair (post-quantum key encapsulation)

Two files are written to the working directory:

| File | Contents | Keep secret? |
|------|----------|--------------|
| `server_keys.conf` | Full keypair (public + private keys) | **Yes — never share** |
| `server_pub.conf` | Public keys only (X25519 + ML-KEM encapsulation key) | No — distribute to clients |

The public keys are also printed to the console:

```
=== Public Keys (share these with peers) ===
x25519_public = <64 hex chars>
mlkem_ek = <2368 hex chars>
============================================
```

### Subsequent Runs

On every subsequent start the server reloads keys from the existing `server_keys.conf`. No new keys are generated.

### Server Configuration

On first run the server also creates `server.conf` with defaults if it does not exist:

```ini
# PostQuantumVPN Server Configuration
bind_ip = 0.0.0.0
port    = 51820
```

Edit this file before starting the server if you need to bind to a specific interface or use a different port. The server listens on UDP.

### TUN Interface

The server brings up a TUN interface named `pqvpn0` with the VPN-side address `10.8.0.1`. This is the gateway address that clients route traffic through.

---

## Step 2: Distribute the Server's Public Keys to the Client Machine

The client must have a copy of `server_pub.conf` in its working directory before it can connect. Copy the file from the server machine:

```bash
# On the client machine
scp user@server-host:/path/to/PostQuantumVPN/server_pub.conf .
```

Or copy the contents manually. The file looks like:

```ini
# PostQuantumVPN Server Public Keys
# Copy this file to the client machine.

x25519_public = <64 hex chars>
mlkem_ek = <2368 hex chars>
```

> If `server_pub.conf` is missing or malformed, the client will refuse to start with the error:
> `main: Cannot start without server public keys`

---

## Step 3: Configure the Client

On first run the client creates `client.conf` with defaults if it does not exist:

```ini
# PostQuantumVPN Client Configuration
server_ip   = 127.0.0.1
server_port = 51820
```

Edit `client.conf` to point to the actual server before starting:

```ini
server_ip   = <server's public IP address>
server_port = 51820
```

---

## Step 4: Start the Client

From the repository root on the **client machine**:

```bash
sudo ./bin/PQ_VPN_Client
```

Or use the make shortcut:

```bash
sudo make run-client
```

### First Run — Client Key Generation

Like the server, the client generates its own keypair on first run and saves it to `client_keys.conf`. These are the client's long-term static keys used in the handshake. Keep this file private.

### Handshake and Session Establishment

After loading its keys and `server_pub.conf`, the client:

1. Sends a **Handshake Initiation** message to the server (hybrid ML-KEM + X25519 key exchange)
2. Receives a **Handshake Response** from the server
3. Derives symmetric session keys via HKDF
4. Brings up the `tun0` TUN interface
5. Begins routing encrypted traffic through the tunnel

A successful connection produces a log line on the server similar to:

```
Server: Session established  peer=<client-ip>:<port>  local_idx=...  remote_idx=...
```

---

## Step 5: Stopping the Client or Server

Type `q` and press **Enter** in the terminal running either binary:

```
q
```

This triggers a clean shutdown: the event loop stops, the TUN interface is torn down, and the UDP socket is closed.

---

## Summary of Files

| File | Created by | Location | Purpose |
|------|-----------|----------|---------|
| `server_keys.conf` | Server (first run) | Server working dir | Server's full keypair — keep private |
| `server_pub.conf` | Server (every run) | Server working dir → copy to client | Server's public keys for client distribution |
| `server.conf` | Server (first run) | Server working dir | Server bind address and port |
| `client_keys.conf` | Client (first run) | Client working dir | Client's full keypair — keep private |
| `client.conf` | Client (first run) | Client working dir | Server IP/port the client connects to |
