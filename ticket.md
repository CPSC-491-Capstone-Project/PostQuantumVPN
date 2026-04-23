The client currently forwards plaintext packets. This ticket adds the handshake initiator and encrypts all Transport traffic through the existing session module. After this ticket, the client can initiate a hybrid X25519 + ML-KEM-768 handshake, complete it upon receiving a Response, activate an encrypted session, and encrypt/decrypt all tunneled packets with ChaCha20-Poly1305.

Assume the session module (Seal, Open, replay window, SessionManager, SerializeTransport, DeserializeTransport) is complete.

Client key material:

The Client class must hold its own static X25519 key pair, its own static ML-KEM-768 key pair, the server's static X25519 public key (pre-shared, loaded from configuration), and a core::utils::Tai64n instance for generating timestamps. These are loaded or generated during Init().

Replace the SendInitiation() stub:

Initialize chaining key and hash from InitialChainingKey() / InitialHash().

Walk the Noise IK initiator steps: MixHash the server's static X25519 public key, generate an ephemeral X25519 key pair, MixHash the ephemeral public key, DH(ephemeral_private, server_static_public), MixKey, EncryptAndHash the client's static X25519 public key.

DH(client_static_private, server_static_public), MixKey, EncryptAndHash a TAI64N timestamp.

ML-KEM-768 encapsulation against the server's ML-KEM public key, MixKey the shared secret.

Serialize the Initiation: message type 0x01, sender index (locally generated uint32_t), ephemeral public key, encrypted static key, encrypted timestamp, ML-KEM ciphertext, MAC fields.

Send via socket.SendTo(server_endpoint, initiation).

Store the in-progress handshake state (chaining key, hash, ephemeral private key) so HandleResponse can complete the handshake.

If any cryptographic operation returns std::nullopt, log at Error and abort the attempt. The loop continues running and can retry.

Replace the HandleResponse() stub:

Validate minimum message length.

Deserialize: responder sender index, responder ephemeral public key, encrypted empty payload, MAC fields.

Verify MAC1.

Resume the stored handshake state (chaining key, hash, ephemeral private key from SendInitiation). MixHash the responder's ephemeral public key.

DH(client_ephemeral_private, responder_ephemeral), MixKey.

DH(client_static_private, responder_ephemeral), MixKey.

DecryptAndHash the encrypted empty payload — if this fails, the handshake is corrupted. Log and discard.

Derive session keys via KDF2(C, empty) → (T0, T1). The client's send_key = T0 and recv_key = T1.

Call session_manager.ActivateSession(secrets, server_endpoint). Log at Info on success.

After this, the client has an active Session with traffic keys.

Replace the plaintext forwarding with encrypted Transport:

Outbound (TUN → UDP): Instead of wrapping in the simple framing header, call session->Seal(ip_packet) to encrypt, then SerializeTransport(receiver_index, counter, encrypted) to build the wire-format Transport message. Send via socket.SendTo(server_endpoint, transport_message).

Inbound (UDP → TUN): Instead of stripping the simple framing header, call DeserializeTransport(data) to parse the Transport header. Look up the session via session_manager.FindByIndex(header.receiver_index). Call session->Open(header.counter, header.encrypted_payload) to decrypt. Discard on failure. On success, write the plaintext IP packet into the TUN.

Keepalives and session expiry:

In TimerTick(), call session_manager.GetKeepaliveDue(). For each, CreateKeepalive() → SerializeTransport → SendTo. Check session->IsExpired() and remove dead sessions. If the only session expires, re-initiate a handshake by calling SendInitiation() again.

Rekey can be deferred — kRekeyAfterMessages (2^60) and kRekeyAfterTime (120 seconds) are generous enough for a demo. If time permits, trigger a new handshake when NeedsRekey() returns true.

Tests:

Call SendInitiation with known test keys, capture the UDP datagram, verify byte 0 is 0x01 and total length matches the expected Initiation size.

Execute a full Initiation → Response → HandleResponse round-trip over loopback with known keys on both sides. Verify the client's send_key matches what the server would compute as its recv_key, and vice versa.

Feed a Response with a corrupted encrypted payload — DecryptAndHash fails, handshake aborted.

curl http://example.com through the tunnel — HTTP response received.

tcpdump on the UDP port — payloads are encrypted, not readable cleartext.


