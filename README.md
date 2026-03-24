# Lightweight VPN — Complete Build (Phases 1–4)

## File Overview

| File | Purpose |
|------|---------|
| `hello_tun.c` | Phase 1a — TUN device creation test |
| `local_vpn.c` | Phase 1b — Local tun0↔tun1 packet bridge |
| `vpn_client_full.c` | Phase 2+3+4 — Full VPN client |
| `vpn_server_full.c` | Phase 2+3+4 — Full VPN server |
| `Makefile` | Build all targets |

---

## Prerequisites

```bash
sudo apt install gcc libssl-dev
```

---

## Build

```bash
make
# or individually:
gcc vpn_server_full.c -o vpnserver -lssl -lcrypto -lpthread
gcc vpn_client_full.c -o vpnclient -lssl -lcrypto
```

---

## Phase 1 — Local TUN Test

```bash
# Test 1: Create a single TUN device
sudo ./hello_tun

# Test 2: Bridge two local TUN devices (simulate VPN without network)
sudo ./local_vpn
# In another terminal:
sudo ip addr add 10.0.0.1/24 dev tun0
sudo ip addr add 10.0.0.2/24 dev tun1
sudo ip link set tun0 up
sudo ip link set tun1 up
ping 10.0.0.2   # packets bridge through local_vpn
```

---

## Phase 2+3 — Encrypted Multi-Client VPN

### Server (machine A)

```bash
# Terminal 1 — run server
sudo ./vpnserver

# The server auto-configures tun0 as 10.8.0.1/24
# IP pool: 10.8.0.2 – 10.8.0.254 (253 clients)
```

### Client (machine B)

```bash
sudo ./vpnclient <SERVER_IP>

# VPN tunnel will be active.
# The server assigns a virtual IP automatically (e.g. 10.8.0.2).
# Test connectivity:
ping 10.8.0.1
```

### Multiple clients

Just run `./vpnclient <SERVER_IP>` on multiple machines simultaneously.  
Each gets a unique IP from the pool. Sessions expire after 5 minutes of inactivity.

---

## Phase 4 — Full Internet Routing via VPN

### Step 1 — Set up NAT on server (run once)

```bash
# Replace eth0 with your actual WAN interface
sudo ./vpnserver --setup-nat eth0
```

This runs:
- `echo 1 > /proc/sys/net/ipv4/ip_forward`
- `iptables -t nat -A POSTROUTING -s 10.8.0.0/24 -o eth0 -j MASQUERADE`
- `iptables -A FORWARD -i tun0 -o eth0 -j ACCEPT`
- `iptables -A FORWARD -i eth0 -o tun0 -m state --state RELATED,ESTABLISHED -j ACCEPT`

### Step 2 — Start server normally

```bash
sudo ./vpnserver
```

### Step 3 — Connect client with full tunnel

```bash
sudo ./vpnclient <SERVER_IP> --full-tunnel
```

The client will:
1. Complete DH handshake + receive IP
2. Save current default gateway
3. Route all traffic through VPN TUN
4. Set DNS to 8.8.8.8 via VPN
5. On Ctrl+C: restore original routes + DNS

### Verify

```bash
# Check your public IP (should show server's IP)
curl ifconfig.me

# Check DNS
nslookup google.com

# Ping
ping 8.8.8.8
```

---

## Protocol Reference

| Byte | Field | Notes |
|------|-------|-------|
| 0 | type | 0x01=INIT, 0x02=RESP, 0x03=IP_ASSIGN, 0x04=DATA, 0x05=KEEPALIVE, 0x06=DISCONNECT |
| 1-2 | length | uint16 big-endian, payload byte count |
| 3+ | data | payload |

**DATA payload layout:**
```
[ 12 bytes IV ][ 16 bytes GCM Tag ][ N bytes AES-256-GCM ciphertext ]
```

---

## Security Features

- **AES-256-GCM** — authenticated encryption, detects tampering
- **Diffie-Hellman RFC 7919 ffdhe2048** — forward-secure key exchange
- **Per-session keys** — each client has an independent AES key
- **Random IV** — fresh 12-byte IV per packet (RAND_bytes)
- **Keepalive** — 30-second heartbeat detects dead clients
- **Session timeout** — idle sessions freed after 300 seconds
- **Graceful disconnect** — MSG_DISCONNECT releases IP pool slot immediately

---

## Troubleshooting

| Problem | Fix |
|---------|-----|
| `open /dev/net/tun: Permission denied` | Run as root (`sudo`) |
| `ioctl TUNSETIFF: Device or resource busy` | Another process has `tun0`; kill it or rename |
| Handshake timeout | Check firewall allows UDP port 5555 |
| Packets not forwarded | Confirm `ip_forward=1` and iptables rules |
| Client can't reach internet | Re-run `--setup-nat` and check WAN iface name |
