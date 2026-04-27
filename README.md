# knockd 

A lightweight security daemon written in C that hides services behind a secret sequence of connection attempts. In its default state, SSH (port 22) is completely firewalled. Only a client that "knocks" on the right ports in the right order gets temporary access — automatically revoked after 30 seconds.

No open ports. No listening sockets. No trace. Just a raw packet sniffer watching in silence.

---

## How It Works

```
Client knocks:   TCP SYN → 7000 → 8000 → 9000
                                  ↓
Daemon detects:  Raw socket sniffs SYN packets, tracks sequence per IP
                                  ↓
Firewall opens:  iptables -I INPUT -s <YOUR_IP> -p tcp --dport 22 -j ACCEPT
                                  ↓
30 seconds pass: Rule is automatically removed
```

The sniffer uses `AF_PACKET` raw sockets — it captures packets at the network level without binding to any port, making the daemon completely invisible to port scanners.


---

## Requirements

Fedora (or any Linux with raw socket support):

```bash
sudo dnf groupinstall "Development Tools"
sudo dnf install gcc make nmap iptables-nft
```

> The daemon must run as **root** — raw sockets (`AF_PACKET`) and `iptables` both require it.

---

## Configuration

Edit `include/config.h` before building to set your knock sequence and timeouts:

```c
/* Secret knock sequence */
static const uint16_t KNOCK_SEQUENCE[] = { 7000, 8000, 9000 };
#define KNOCK_SEQ_LEN   3

/* Port to unlock after a successful knock */
#define PROTECTED_PORT  22

/* Seconds before access is automatically revoked */
#define ACCESS_TIMEOUT  30

/* Max seconds allowed between consecutive knocks */
#define KNOCK_WINDOW    15
```

---

## Build

```bash
make          # optimised build
make debug    # debug symbols, no optimisation
make clean    # remove binary
```

---

## Running

### 1. Set up the firewall

>  If you are already connected via SSH, run the first line **before** blocking port 22 or you will disconnect yourself.

```bash
# Keep existing connections alive
sudo iptables -I INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

# Block SSH by default
sudo iptables -A INPUT -p tcp --dport 22 -j DROP
```

### 2. Start the daemon

```bash
sudo ./knockd        # normal mode
sudo ./knockd -v     # verbose — prints every knock and state change
```

### 3. Send the knock sequence

From any machine with `nmap` (or use the included script):

```bash
# Using the client script
./knock_client.sh <server-ip>

# With automatic SSH after knocking
./knock_client.sh <server-ip> --ssh

# Or manually with nmap
nmap -Pn --max-retries 0 -p 7000 <server-ip> && sleep 0.5
nmap -Pn --max-retries 0 -p 8000 <server-ip> && sleep 0.5
nmap -Pn --max-retries 0 -p 9000 <server-ip>
```

### 4. SSH in

```bash
ssh user@<server-ip>
# You have 30 seconds — port closes automatically after that
```

### 5. Stop the daemon

Press `Ctrl+C`. The daemon catches `SIGINT`/`SIGTERM` and removes every iptables rule it added before exiting. The firewall is left exactly as it was.

---

## Verbose Output (what to expect)

![alt text](image.png)
---

## Security Notes

- **No shell injection** — `iptables` is invoked via `fork()`/`execv()`, never `system()`
- **IP validation** — all IPs pass through `inet_ntop()` before being used in any command
- **Per-IP rules** — only the knocking IP is granted access, not the whole network
- **Auto-cleanup** — `Ctrl+C` or `kill` triggers graceful removal of all added rules
- **Invisible** — no ports are bound; the daemon cannot be found by a port scan

---

## Troubleshooting

| Symptom | Fix |
|---|---|
| `must be run as root` | Use `sudo ./knockd` |
| `Failed to create raw socket` | Confirm you are root and on Linux (not macOS) |
| Knocks not detected | Run `sudo tcpdump -i any port 7000` to verify packets arrive at the machine |
| `iptables` errors | Run `sudo dnf install iptables-nft` and check `iptables -L` |
| Client can't knock | Run `sudo dnf install nmap` |
| Port still blocked after knock | Check `sudo iptables -L INPUT -n` — the ACCEPT rule should appear at the top |
