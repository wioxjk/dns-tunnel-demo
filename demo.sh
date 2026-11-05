#!/usr/bin/env bash
# End-to-end loopback demo: start the authoritative server, exfiltrate a file
# over DNS queries, then verify the reassembled file is byte-identical.
set -euo pipefail
cd "$(dirname "$0")"

head -c 5000 /dev/urandom > /tmp/dns-demo-payload.bin

python3 server.py --port 5353 > /tmp/dns-demo-server.log 2>&1 &
SRV=$!
trap 'kill "$SRV" 2>/dev/null || true' EXIT
sleep 0.5

python3 client.py --server 127.0.0.1 --port 5353 --file /tmp/dns-demo-payload.bin --name payload.bin

kill "$SRV" 2>/dev/null || true
trap - EXIT
echo "--- server log (last lines) ---"
tail -n 3 /tmp/dns-demo-server.log
echo "--- integrity check ---"
sha256sum /tmp/dns-demo-payload.bin received/payload.bin
