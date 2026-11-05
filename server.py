#!/usr/bin/env python3
"""Authoritative DNS server that reassembles files encoded in query names.

Authorized homelab / awareness-demo use only, on infrastructure you own.
"""
import argparse
import base64
import hashlib
import os
import socket
import struct

QTYPE_TXT = 16


def b32decode(s):
    return base64.b32decode(s.upper() + "=" * (-len(s) % 8))


def decode_payload(mtype, s):
    if mtype in ("x", "h"):
        return bytes.fromhex(s)
    return b32decode(s)


def parse_query(data):
    if len(data) < 12:
        return None
    qid, flags, qd, _an, _ns, _ar = struct.unpack("!HHHHHH", data[:12])
    if qd < 1 or flags & 0x8000:
        return None
    pos = 12
    labels = []
    while pos < len(data):
        ln = data[pos]
        pos += 1
        if ln == 0:
            break
        labels.append(data[pos:pos + ln].decode("ascii", "replace"))
        pos += ln
    if pos + 4 > len(data):
        return None
    qtype, _qclass = struct.unpack("!HH", data[pos:pos + 4])
    return qid, labels, qtype


def encode_qname(labels):
    return b"".join(bytes([len(l)]) + l.encode() for l in labels) + b"\x00"


def build_response(qid, labels, qtype, txt=b"ack", rcode=0):
    flags = 0x8580 | rcode  # QR + AA + RD + RA
    header = struct.pack("!HHHHHH", qid, flags, 1, 1, 0, 0)
    question = encode_qname(labels) + struct.pack("!HH", qtype, 1)
    rdata = bytes([len(txt)]) + txt
    answer = struct.pack("!HHHIH", 0xC00C, QTYPE_TXT, 1, 0, len(rdata)) + rdata
    return header + question + answer


class Reassembler:
    def __init__(self, outdir):
        self.outdir = outdir
        self.sessions = {}

    def handle(self, labels, zone_labels):
        # wire format: <type>.<payload...>.up.<zone...>
        suffix = ["up"] + zone_labels
        if len(labels) <= len(suffix) or labels[-len(suffix):] != suffix:
            return b"bad-zone", 3
        msg = labels[: -len(suffix)]
        mtype = msg[0]
        try:
            if mtype in ("s", "x") and len(msg) == 4:
                name = decode_payload(mtype, msg[1]).decode("utf-8", "replace")
                total = int(msg[2], 16)
                sess = msg[3]
                self.sessions[sess] = {"name": name, "total": total, "chunks": {}}
                return b"ok-start", 0
            if mtype in ("c", "h") and len(msg) == 4:
                data = decode_payload(mtype, msg[1])
                seq = int(msg[2], 16)
                sess = msg[3]
                self.sessions[sess]["chunks"][seq] = data
                return f"ok-{seq}".encode(), 0
            if mtype == "e" and len(msg) == 4:
                digest = msg[1] + msg[2]
                sess = msg[3]
                s = self.sessions.pop(sess)
                blob = b"".join(s["chunks"][i] for i in range(s["total"]))
                if hashlib.sha256(blob).hexdigest() != digest:
                    return b"bad-hash", 0
                os.makedirs(self.outdir, exist_ok=True)
                path = os.path.join(self.outdir, os.path.basename(s["name"]))
                with open(path, "wb") as f:
                    f.write(blob)
                print(f"[server] received {path} ({len(blob)} bytes, {s['total']} chunks, sha256 ok)", flush=True)
                return b"done", 0
        except Exception as e:
            print(f"[server] error: {e}", flush=True)
            return b"err", 2
        return b"bad-msg", 3


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--bind", default="127.0.0.1", help="default 127.0.0.1; use your LAN IP in the homelab")
    ap.add_argument("--port", type=int, default=5353, help="use 53 on a real authoritative host")
    ap.add_argument("--zone", default="tunnel.local", help="zone this server is authoritative for")
    ap.add_argument("--out", default="received", help="directory for reassembled files")
    args = ap.parse_args()

    zone_labels = args.zone.strip(".").split(".")
    reasm = Reassembler(args.out)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((args.bind, args.port))
    print(f"[server] authoritative for up.{args.zone} on {args.bind}:{args.port}, files -> {args.out}/", flush=True)
    try:
        while True:
            data, addr = sock.recvfrom(4096)
            parsed = parse_query(data)
            if not parsed:
                continue
            qid, labels, qtype = parsed
            print(f"[server] query {addr[0]}:{addr[1]}  {'/'.join(labels)}", flush=True)
            txt, rcode = reasm.handle(labels, zone_labels)
            sock.sendto(build_response(qid, labels, qtype, txt, rcode), addr)
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
