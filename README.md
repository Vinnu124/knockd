# knockd 

A lightweight security daemon written in C that hides services behind a secret sequence of connection attempts. In its default state, SSH (port 22) is completely firewalled. Only a client that "knocks" on the right ports in the right order gets temporary access — automatically revoked after 30 seconds.

No open ports. No listening sockets. No trace. Just a raw packet sniffer watching in silence.

---

## How It Works

```
Client knocks:   TCP SYN or UDP → 7000 → 8000 → 9000
                                  ↓
Daemon detects:  Raw socket sniffs packets, tracks sequence per IP
                                  ↓
Firewall opens:  iptables -I INPUT -s <YOUR_IP> -p tcp --dport 22 -j ACCEPT
                                  ↓
30 seconds pass: Rule is automatically removed
```

The sniffer uses `AF_PACKET` raw sockets, capturing packets at the network level without binding to any port. This makes the daemon completely invisible to port scanners. Both TCP SYN and UDP knocks are supported.

---

## Requirements

Fedora (or any Linux with raw socket support):

```bash
sudo dnf groupinstall "Development Tools"
sudo dnf install gcc make nmap iptables-nft
```

> The daemon must run as **root** — raw sockets (`AF_PACKET`) and `iptables` both require it.

---

## Installation & Configuration

1. Build and install the daemon:
```bash
make
sudo make install
```

2. Edit your configuration file at `/etc/knockd.conf`:
```ini
# Secret sequence of ports
sequence = 7000, 8000, 9000
# Port to unlock after a successful knock
port = 22
# Seconds before access is automatically revoked
timeout = 30
# Max seconds allowed between consecutive knocks
window = 15
```

3. Enable and start the systemd service:
```bash
sudo systemctl enable knockd
sudo systemctl start knockd
```

---

## Running & Knocking

### 1. Set up the firewall

>  If you are already connected via SSH, run the first line **before** blocking port 22 or you will disconnect yourself.

```bash
# Keep existing connections alive
sudo iptables -I INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

# Block SSH by default
sudo iptables -A INPUT -p tcp --dport 22 -j DROP
```

### 2. Send the knock sequence

From any machine with `nmap` (or use the included script):

```bash
# Using the client script
./knock_client.sh <server-ip>

# With automatic SSH after knocking
./knock_client.sh <server-ip> --ssh

# (Optional) Use the --udp flag as well 
./knock_client.sh <server-ip> --udp

# Or manually with nmap
nmap -Pn --max-retries 0 -p 7000 <server-ip> && sleep 0.5
nmap -Pn --max-retries 0 -p 8000 <server-ip> && sleep 0.5
nmap -Pn --max-retries 0 -p 9000 <server-ip>
```

### 3. SSH in

```bash
ssh user@<server-ip>
# You have 30 seconds — port closes automatically after that
```

### 4. Viewing Logs

Since `knockd` runs as a systemd service, its logs are safely stored in the journal:
```bash
# Watch live logs
sudo journalctl -u knockd -f
```

---

## Verbose Output (what to expect)

![alt text](image.png)
---

## Security Notes

- **No shell injection** — `iptables` is invoked via `fork()`/`execv()`, never `system()`
- **IP validation** — all IPs pass through `inet_ntop()` before being used in any command
- **Per-IP rules** — only the knocking IP is granted access, not the whole network
- **Auto-cleanup** — `systemctl stop knockd` triggers graceful removal of all added rules
- **Invisible** — no ports are bound; the daemon cannot be found by a port scan

---

## Troubleshooting

| Symptom | Fix |
|---|---|
| `Failed to create raw socket` | Confirm you are root and on Linux (not macOS) |
| Knocks not detected | Run `sudo tcpdump -i any port 7000` to verify packets arrive at the machine |
| `iptables` errors | Run `sudo dnf install iptables-nft` and check `iptables -L` |
| Client can't knock | Run `sudo dnf install nmap` |
| Port still blocked after knock | Check `sudo iptables -L INPUT -n` — the ACCEPT rule should appear at the top |
