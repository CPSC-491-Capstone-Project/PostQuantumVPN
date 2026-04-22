This ticket turns the client event loop stub into a working plaintext tunnel endpoint. After this ticket, applications on the client machine have their traffic captured by the TUN device, forwarded in cleartext over UDP to the server, and responses are delivered back to the application. The application sees normal internet access, unaware it is being tunneled. No encryption — the goal is to prove the client-side network plumbing and routing work.

Assume the SessionManager is set up and a session entry exists for the server. Assume the TunDevice class already exists in core/network/ with Open, Read, Write, GetHandle, and Close methods.

Client network setup (run once at startup via a setup script, outside the Client class):

ip addr add 10.0.0.2/24 dev tun0
ip link set tun0 up
ip route add default via 10.0.0.2 dev tun0 table 100
ip rule add not fwmark 51820 table 100

The fwmark routing rule is the critical piece for loop prevention. The VPN's own UDP socket is marked with SO_MARK = 51820 so its packets bypass the TUN and use the normal routing table. All other traffic — including DNS on port 53 — gets routed into the TUN by the policy rule.

Modify the client event loop:

Add a TunDevice member to the Client class. Open it during Init() and register its fd with the event poller alongside the UDP socket (both EventMask::Readable). Also during Init(), set SO_MARK = 51820 on the UDP socket via setsockopt.

TUN is readable (application sends a packet): Read an IP packet from the TUN. Look up the active session (only one for now). Wrap the raw packet in a simple framing header: [type=0x04 (1 byte)] [receiver_index (4 bytes LE)] [length (2 bytes LE)] [raw IP packet]. Send via socket.SendTo(server_endpoint, framed). The SO_MARK ensures this outbound UDP packet uses the normal routing table and does not re-enter the TUN.

UDP is readable (response from server): Receive the datagram. Strip the framing header. Write the raw IP packet into the TUN via tun.Write(payload). The kernel delivers it to the application that originally made the request.

Routing and loop prevention — things to watch for:

If SO_MARK is not set on the UDP socket, the VPN's own packets enter the TUN and create an infinite loop. This is the #1 debugging issue.

The ip rule must use not fwmark (not fwmark) — the logic is inverted from what you might expect.

DNS traffic must also enter the TUN. The default route in table 100 covers this.

If the server is on the same LAN, you may need a more specific route for the server's IP to bypass the TUN: ip route add <server_ip>/32 via <gateway> table main.

Tests (manual — requires root and a running server or a mock UDP echo):

Start a UDP echo (or the real server), start the client, run ping 8.8.8.8 — ICMP packets traverse the tunnel and return.

curl http://example.com — HTTP response received.

VPN's own UDP traffic does not enter the TUN (no routing loop).

Kill the remote server — client stops receiving responses but does not crash.


