# nettrap

**Network isolation for untrusted commands.** nettrap wraps any command inside a Linux network namespace with a controlled, filtered egress path. Every DNS query and TCP/UDP connection passes through nettrap's proxy and firewall — providing kernel-enforced isolation that cannot be bypassed from userspace.

## Why?

You download a pentest tool from GitHub. Before running it against your target, you want guarantees:

- It won't phone home to a C2 server
- It won't exfiltrate your scope data to a third-party API
- It won't contact anything outside your authorized target

nettrap provides those guarantees at the kernel level.

## Quick Start

```bash
# Build
make build

# Install
sudo make install

# Run curl with network logging
sudo nettrap --analyse -- curl https://example.com

# Only allow traffic to target.com
sudo nettrap --allow "target.com,*.target.com" -- python3 recon_tool.py -t target.com

# Approve each connection interactively
sudo nettrap --interactive -- ./suspicious_binary --target 10.10.10.5
```

## Modes

### Allow Mode (`--allow` / `--allow-file`)

Strict whitelist. Only specified domains, IPs, and CIDRs are reachable. Everything else is silently dropped.

```bash
# Comma-separated allow-list
sudo nettrap --allow "target.com,*.target.com,10.10.10.0/24" -- nmap -sV target.com

# From a file
sudo nettrap --allow-file scope.txt -- python3 tool.py

# Combined
sudo nettrap --allow "api.shodan.io" --allow-file scope.txt -- python3 recon.py
```

**Allow-list file format:**
```
# One entry per line. Supports: domains, wildcard domains, IPs, CIDRs
target.com
*.target.com
10.10.10.0/24
93.184.216.34
```

### Analyse Mode (`--analyse`)

Unrestricted network access with full logging. See exactly what a tool does before you trust it.

```bash
sudo nettrap --analyse -- python3 unknown_tool.py --target 10.10.10.5
sudo nettrap --analyse --pcap /tmp/capture.pcapng -- ./suspicious_binary
```

### Interactive Mode (`--interactive`)

Default-deny with per-destination user approval. Maximum caution.

```bash
sudo nettrap --interactive -- ruby exploit.rb -r 10.10.10.5
```

Each new destination prompts:
```
[nettrap] ┌─ New connection ────────────────────────────────
[nettrap] │ Destination: 93.184.216.34:443 (example.com)
[nettrap] │ Protocol:    TCP
[nettrap] └─────────────────────────────────────────────────
[nettrap] Allow? [y]es / [n]o / [a]lways (domain) / [d]etails: a
[nettrap] Whitelisted: example.com (and all resolved IPs)
```

## Options

| Flag | Default | Description |
|------|---------|-------------|
| `--log <path>` | `./nettrap-<sid>-<ts>.json` | JSON log output path |
| `--no-log` | false | Disable JSON log file |
| `--pcap <path>` | — | Capture traffic to pcapng file |
| `--host-port <ports>` | — | Expose host loopback ports (see below) |
| `--quiet` / `-q` | false | Suppress real-time stderr output |
| `--verbose` / `-v` | false | Show debug output |
| `--dns-upstream <ip>` | system default | Upstream DNS server |
| `--timeout <secs>` | 30 | Interactive mode auto-deny timeout |
| `--dry-run` | false | Show config without executing |
| `--ipv6` | false | Enable IPv6 in namespace |

## Proxy / Burp Suite Support

Tools often route through intercepting proxies (`--proxy http://127.0.0.1:8080`). Since the wrapped command runs in an isolated namespace, `127.0.0.1` refers to the namespace's loopback — not the host's. `--host-port` bridges this gap:

```bash
# Route through Burp Suite on port 8080
sudo nettrap --allow "target.com" --host-port 8080 \
    -- gobuster dir -u https://target.com --proxy http://127.0.0.1:8080

# Multiple ports (Burp + SOCKS)
sudo nettrap --allow-file scope.txt --host-port 8080,1080 \
    -- python3 tool.py --proxy http://127.0.0.1:8080
```

Traffic flow: tool → namespace DNAT → veth bridge → host DNAT → `127.0.0.1:8080` (Burp).

**Note:** Traffic through exposed host ports exits via the host's network stack, bypassing nettrap's allow-list. This is by design — only expose ports to services you trust.

## Output

### Real-time stderr

```
[nettrap] Session a3f8 started
[nettrap] Namespace: nettrap-a3f8 | Subnet: 10.200.42.0/24
[nettrap] Mode: allow | 2 domains, 1 CIDRs
[nettrap] Executing: python3 tool.py -t target.com
[nettrap] ───────────────────────────────────────────────
[nettrap] 14:30:22 DNS  ALLOWED  target.com → 93.184.216.34
[nettrap] 14:30:22 TCP  ALLOWED  93.184.216.34:443 (target.com)
[nettrap] 14:30:23 DNS  BLOCKED  telemetry.evil.io
[nettrap] ───────────────────────────────────────────────
[nettrap] Session a3f8 finished (exit code 0, duration 5.2s)
```

### JSON log

Written to `./nettrap-<sid>-<timestamp>.json` by default. Contains full session metadata, all DNS queries, all connections, and summary statistics. Disable with `--no-log`.

### PCAP capture

`--pcap <path>` writes pcapng format (Wireshark-compatible) capturing all traffic on the veth bridge. Useful for protocol-level analysis (TLS SNI, certificate inspection, connection patterns). Note: TLS payloads are encrypted — nettrap does not perform MITM.

## Installation

### Requirements

- Linux (kernel 4.x+)
- Go 1.22+ (build only)
- Root privileges (`sudo`)
- `conntrack` package (optional, for connection event monitoring: `apt install conntrack`)

### From source

```bash
git clone https://github.com/p4th0r/nettrap.git
cd nettrap
make build
sudo make install
```

nettrap requires root privileges. All commands should be run with `sudo`:

```bash
sudo nettrap --analyse -- curl -s https://example.com
```

### Why not Linux capabilities instead of sudo?

nettrap requires `CAP_SYS_ADMIN` for namespace operations, which is effectively equivalent to root — it grants mount, namespace escape, BPF, and other primitives that trivially escalate to full root. Using `setcap` would provide a false sense of reduced privilege. Running with `sudo` is simpler, more honest, and avoids pitfalls like capabilities being silently cleared when the binary is overwritten.

## Architecture

```
┌─ Host Namespace ──────────────────────────────────────────┐
│                                                           │
│  DNS Proxy (UDP/TCP 53)    nftables Firewall              │
│  ├── Logs all queries      ├── allow: whitelist + DROP    │
│  ├── allow: resolve/refuse ├── analyse: ACCEPT + LOG      │
│  └── Tracks domain→IP      └── interactive: NFQUEUE       │
│                                                           │
│  veth-host-<sid> (10.200.X.1/24)                         │
│  ════════════════════════════════ namespace boundary       │
│  veth-jail-<sid> (10.200.X.2/24)                         │
│                                                           │
│  ┌─ Isolated Namespace: nettrap-<sid> ─────────────────┐│
│  │  resolv.conf → nameserver 10.200.X.1                 ││
│  │  default route → 10.200.X.1                          ││
│  │  IPv6 disabled (unless --ipv6)                       ││
│  │                                                       ││
│  │  $ <your command runs here>                          ││
│  └───────────────────────────────────────────────────────┘│
└───────────────────────────────────────────────────────────┘
```

All traffic from the wrapped command must traverse the veth bridge. The DNS proxy intercepts all name resolution. The nftables firewall controls all IP-level traffic. This is kernel-enforced — it cannot be bypassed from userspace regardless of the tool's language, compilation, or syscall strategy.

### Privilege separation

nettrap uses a split-privilege architecture:

| Component | Runs as | Why |
|-----------|---------|-----|
| Namespace setup | root | Kernel requires it |
| DNS proxy | root | Binds to privileged veth interface |
| nftables firewall | root | Firewall manipulation requires it |
| NFQUEUE handler | root | Packet interception requires it |
| **Wrapped command** | **your user** | **No root needed — and safer without it** |

The tool you're sandboxing has no root access by default. It can't read `/etc/shadow`, can't modify system files, can't kill processes outside its namespace, and can't alter the firewall rules confining it.

If the wrapped tool needs root (e.g., raw socket scanning with nmap `-sS`), use `--run-as-root`:

```bash
sudo nettrap --allow "target.com" --run-as-root -- nmap -sS target.com
```

Log and PCAP output files are automatically `chown`'d to your user after the session, so you don't need sudo to read them.

## Cleanup

If nettrap is killed with SIGKILL (or crashes), resources may be left behind. Clean them up:

```bash
sudo nettrap cleanup
```

This removes orphaned namespaces (`nettrap-*`), veth pairs (`veth-host-*`/`veth-jail-*`), nftables tables (`nettrap_*`), and temp files.

## Shell Completions

```bash
# Bash
source <(nettrap completion bash)

# Zsh
source <(nettrap completion zsh)

# Fish
nettrap completion fish | source
```

## Troubleshooting

### Tool fails with "permission denied" inside nettrap

By default, the wrapped command runs as your regular user, not root. If the tool needs elevated privileges (e.g., raw sockets, binding to ports below 1024), use `--run-as-root`:

```bash
sudo nettrap --allow "target.com" --run-as-root -- nmap -sS target.com
```

### nettrap says "cannot drop privileges" or "not invoked via sudo"

nettrap detects the calling user via `SUDO_UID`/`SUDO_GID` environment variables set by sudo. If you run nettrap directly as root (e.g., `su -` then `nettrap`), these variables are absent and privilege dropping is not possible. Use `sudo nettrap` instead.

## Known Limitations

1. **Network isolation only** — filesystem, PIDs, and IPC are not isolated. For full isolation, use a container runtime.
2. **Linux only** — network namespaces and nftables are Linux kernel features.
3. **Requires root** — `sudo` is required. No way around this for kernel-enforced isolation.
4. **No encrypted DNS interception** — DoH/DoT queries bypass the DNS proxy. In allow mode, the DoH server itself is blocked unless whitelisted. In analyse mode, a warning is logged.
5. **`--host-port` bypasses filtering** — traffic through exposed host ports exits via the host network stack.
6. **PCAP captures encrypted traffic** — TLS payloads are not decrypted. Use Wireshark's TLS dissector for metadata or pair with a MITM proxy.
7. **Interactive mode reserves stdin** — the wrapped command's stdin is connected to `/dev/null` so nettrap can read user input for prompts.

## License

MIT
