#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
"""Writes seed inputs for the fuzz targets into DIR/<target>/.

Each seed is a request type, an option or a sequence the modem is known to
send. The input formats are described at the top of each fuzz_*.c file.
"""
import os
import struct
import sys

out = sys.argv[1] if len(sys.argv) > 1 else "seeds"


def save(target, name, data):
    d = os.path.join(out, target)
    os.makedirs(d, exist_ok=True)
    with open(os.path.join(d, name), "wb") as f:
        f.write(bytes(data))


def opts(*pairs):
    b = b""
    for o, v in pairs:
        b += o.encode() + b"\0" + str(v).encode() + b"\0"
    return b


def req(op, path, *pairs, mode="octet"):
    p = path if isinstance(path, bytes) else path.encode()
    return bytes([0, op]) + p + b"\0" + mode.encode() + b"\0" + opts(*pairs)


RRQ, WRQ = 1, 2
MODEM = [("blksize", 7680), ("timeoutms", 1000), ("tsize", 0), ("wsize", 10)]
OPTIONS = {
    "blksize": [7680, 512, 8, 65464, 7, 65465, "x", " 512", "+512"],
    "timeoutms": [1000, 1, 255000, 0, 255001],
    "tsize": [0, 52, -1],
    "rsize": [52, 1, 104857600, 0, 104857601],
    "wsize": [10, 1, 256, 0, 257],
    "seek": [0, 5, 16777216, -1, 9223372036854775807],
    "unlink": [0, 1],
    "other": [1],
}

# fuzz_request
n = 0
for opt, values in OPTIONS.items():
    for v in values:
        for mode in (0, 1):
            save("request", f"opt-{opt}-{n}", bytes([mode]) + opts((opt, v)))
            n += 1
save("request", "opt-modem", bytes([0]) + opts(*MODEM))
save("request", "opt-unterminated", bytes([1]) + b"blksize\0" + b"512")
save("request", "opt-novalue", bytes([1]) + b"blksize\0")
paths = ["/readwrite/a", "/readwrite/new", "/readwrite/sub/b",
         "/readonly/firmware/image/f1.bin",
         "/readonly/firmware/modem_pr/so/901_0_0.mbn",
         "/readonly/vendor/firmware/f1.bin",
         "/readonly/vendor/firmware_mnt/image/s.bin",
         "/readwrite/../outside/secret", "/readwrite//etc/passwd", "/other"]
for i, path in enumerate(paths):
    save("request", f"rrq-{i}", bytes([2]) + req(RRQ, path, *MODEM)[2:])
    save("request", f"rrq-noopt-{i}", bytes([2]) + req(RRQ, path)[2:])
    save("request", f"wrq-{i}", bytes([3]) + req(WRQ, path, ("blksize", 7680), ("wsize", 10))[2:])
    save("request", f"wrq-noopt-{i}", bytes([3]) + req(WRQ, path)[2:])
    save("request", f"unlink-{i}", bytes([3]) + req(WRQ, path, ("unlink", 0))[2:])
save("request", "rrq-netascii", bytes([2]) + req(RRQ, "/readwrite/a", mode="netascii")[2:])
save("request", "rrq-rsize", bytes([2]) + req(RRQ, paths[3], ("rsize", 52), ("seek", 4))[2:])
save("request", "wrq-seek", bytes([3]) + req(WRQ, "/readwrite/a", ("seek", 3))[2:])

# fuzz_translate
tpaths = paths + [
    "/readwrite/./a", "/readwrite/ln", "/readwrite/dln/secret", "/readwrite/subln/b",
    "/readwrite/sub/.", "/readwrite/.", "/readwrite/", "/readwrite/ota_firewall/ruleset",
    "/readonly/firmware/image/link.bin", "/readonly/firmware/image/odd name\t!.bin",
    "/readonly/firmware/image/sub/x.bin", "/readonly/firmware/image/",
    "/readonly/firmware/modem_pr", "/readonly/firmware/modem_prx",
    "/readwrite/" + "n" * 255, "/readwrite/" + "n" * 256,
    "/readonly/firmware/image/" + "d/" * 2000 + "f",
    "/readwrite/a/../../x", "/readwrite/...", "/readwrite/..a", "..", "/..", "//",
]
for i, path in enumerate(tpaths):
    for op in (0, 1, 2):
        save("translate", f"path-{op}-{i}", bytes([op]) + path.encode())
for i in range(8):
    save("translate", f"prefix-{i}", bytes([4 | (i << 3)]) + b"f1.bin")

# fuzz_session
def MAIN(data, node=0, port=0):
    return bytes([1, node | port << 2]) + struct.pack("<H", len(data)) + data


def RAW(data, k=0, who=0):
    return bytes([2, k, who]) + struct.pack("<H", len(data)) + data


def NEXT(k=0, who=0, delta=0, ln=0):
    return bytes([3, k, who, delta & 0xff]) + struct.pack("<H", ln)


def CTRL(how=0, cmd=0, node=0, port=0, short=0):
    return bytes([4, how, cmd, node, port, short])


def TIMER(ms):
    return bytes([0]) + struct.pack("<H", min(ms // 8, 65535))


def FAIL(n):
    return bytes([5, n])


ro = "/readonly/firmware/image/modem_pr/so/901_0_0.mbn"
seeds = {
    "mcfg": [0] + list(
        MAIN(req(RRQ, "/readwrite/mcfg.tmp", *MODEM)) +
        MAIN(req(WRQ, "/readwrite/mcfg.tmp", ("blksize", 7680), ("timeoutms", 1000), ("wsize", 10))) +
        NEXT(ln=0) +
        MAIN(req(WRQ, "/readwrite/mcfg.tmp", ("blksize", 7680), ("seek", 0), ("wsize", 10))) +
        NEXT(ln=1) +
        MAIN(req(RRQ, "/readwrite/mcfg.tmp", *MODEM)) +
        RAW(b"\0\5\0\x09End of Transfer\0") +
        MAIN(req(WRQ, "/readwrite/mcfg.tmp", ("blksize", 7680), ("unlink", 0)))),
    "read-rsize": [0] + list(
        MAIN(req(RRQ, ro, ("blksize", 7680), ("rsize", 52), ("wsize", 10), ("seek", 0))) +
        NEXT() + NEXT(delta=0)),
    "read-big": [0] + list(
        MAIN(req(RRQ, "/readonly/firmware/image/big.bin", ("blksize", 512),
                 ("rsize", 70000), ("wsize", 10))) + NEXT() * 20),
    "read-noopt": [0] + list(MAIN(req(RRQ, "/readwrite/big")) + NEXT() * 3),
    "write-big": [0] + list(
        MAIN(req(WRQ, "/readwrite/w", ("blksize", 512), ("wsize", 4))) +
        NEXT(ln=512) * 30 + NEXT(ln=10)),
    "write-noopt": [0] + list(MAIN(req(WRQ, "/readwrite/w")) + NEXT(ln=512) + NEXT(ln=3)),
    "write-sub-seek": [2] + list(
        MAIN(req(WRQ, "/readwrite/sub/b", ("blksize", 65464), ("wsize", 16), ("seek", 2000000))) +
        NEXT(ln=65464) * 16),
    "write-new-full": [1] + list(
        MAIN(req(WRQ, "/readwrite/new1", ("blksize", 512))) + NEXT(ln=1) +
        MAIN(req(WRQ, "/readwrite/sub/new2", ("blksize", 512))) + NEXT(ln=1)),
    "write-bytes-full": [2] + list(
        MAIN(req(WRQ, "/readwrite/a", ("blksize", 65464), ("wsize", 16), ("seek", 0))) +
        NEXT(ln=65464) * 16),
    "idle": [0] + list(
        MAIN(req(RRQ, "/readwrite/a", ("blksize", 512))) + TIMER(60000) + TIMER(60000) +
        TIMER(60000)),
    "stray": [0] + list(
        MAIN(req(WRQ, "/readwrite/w", ("blksize", 512), ("wsize", 2))) +
        NEXT(who=1, ln=512) + NEXT(who=3, ln=512) + RAW(b"\0\3\0\1abc", who=5) +
        NEXT(ln=512) + NEXT(ln=1)),
    "ctrl": [0] + list(
        MAIN(req(RRQ, "/readwrite/a", ("blksize", 512)), node=0) +
        MAIN(req(RRQ, "/readwrite/a", ("blksize", 512)), node=1, port=1) +
        CTRL(how=1, cmd=0, node=0) + CTRL(how=2, cmd=0, node=0) +
        CTRL(how=0, cmd=1, node=1, port=1) + CTRL(how=0, cmd=0, node=0) +
        CTRL(how=0, cmd=2) + CTRL(how=0, cmd=3)),
    "ctrl-short": [0] + list(CTRL(how=0x80, short=4)),
    "many": [0] + list(b"".join(
        MAIN(req(RRQ, "/readwrite/a", ("blksize", 8)), node=i % 3, port=i % 3)
        for i in range(70))),
    "fail": [0] + list(
        FAIL(0) + MAIN(req(RRQ, "/readwrite/a", ("blksize", 512))) +
        FAIL(2) + MAIN(req(WRQ, "/readwrite/w", ("blksize", 512))) +
        FAIL(4) + MAIN(req(WRQ, "/readwrite/w", ("blksize", 512))) +
        FAIL(1) + MAIN(req(RRQ, "/readwrite/a", ("blksize", 512))) +
        FAIL(3) + MAIN(req(WRQ, "/readwrite/w", ("blksize", 512)))),
    "odd-main": [0] + list(
        MAIN(b"\0\5\0\1oops\0") + MAIN(b"\0\5") + MAIN(b"\x80\x01") + MAIN(b"\0\3\0\1") +
        MAIN(b"\0\4\0\1") + MAIN(b"\0") + MAIN(b"\0\5\x80\x01x")),
    "unlink": [0] + list(
        MAIN(req(WRQ, "/readwrite/ln", ("unlink", 0))) +
        MAIN(req(WRQ, "/readwrite/sub", ("unlink", 0))) +
        MAIN(req(WRQ, "/readwrite/a", ("unlink", 0)))),
    "dir-read": [0] + list(MAIN(req(RRQ, "/readwrite/.", ("tsize", 0))) +
                           MAIN(req(RRQ, "/readwrite/sub", ("tsize", 0)))),
}
for name, data in seeds.items():
    save("session", name, data)

# fuzz_transfer: kind, opts, option values, events
def TR(kind, blksize=None, wsize=None, rsize=None, seek=None, tsize=None, timeoutms=None):
    o = 0
    b = b""
    if blksize is not None:
        o |= 1; b += struct.pack("<H", blksize)
    if wsize is not None:
        o |= 2; b += bytes([wsize - 1])
    if rsize is not None:
        o |= 4; b += struct.pack("<I", rsize)
    if seek is not None:
        o |= 8; b += struct.pack("<I", seek)
    if tsize is not None:
        o |= 16; b += bytes([tsize])
    if timeoutms is not None:
        o |= 32; b += struct.pack("<H", timeoutms)
    return bytes([kind, o]) + b


def TNEXT(delta=0, ln=0, how=0):
    return bytes([how, delta & 0xff]) + struct.pack("<H", ln)


for f in range(4):
    save("transfer", f"read-{f}", TR(f << 1, blksize=512, wsize=10, rsize=70000) + TNEXT() * 20)
    save("transfer", f"read-rsize-{f}", TR(f << 1, blksize=512, wsize=4, rsize=1024) + TNEXT() * 4)
    save("transfer", f"read-seek-{f}", TR(f << 1, blksize=100, wsize=3, rsize=500, seek=50) + TNEXT() * 5)
    save("transfer", f"read-noopt-{f}", TR(f << 1) + TNEXT() * 2)
    save("transfer", f"write-{f}", TR(1 | f << 1, blksize=512, wsize=4) + TNEXT(ln=512) * 9 + TNEXT(ln=7))
    save("transfer", f"write-seek-{f}", TR(1 | f << 1, blksize=64, wsize=2, seek=5) + TNEXT(ln=64) * 3 + TNEXT(ln=1))
    save("transfer", f"write-noopt-{f}", TR(1 | f << 1) + TNEXT(ln=512) + TNEXT(ln=0))
    save("transfer", f"write-stray-{f}", TR(1 | f << 1, blksize=512, wsize=2) +
         TNEXT(ln=512, how=2) + TNEXT(ln=512, how=6) + TNEXT(ln=512) + TNEXT(ln=1))
save("transfer", "write-wrap", TR(1, blksize=8, wsize=7) + TNEXT(ln=8) * 300)
save("transfer", "write-full", TR(1 | 2 << 3, blksize=65464, wsize=16, seek=0) + TNEXT(ln=65464) * 17)
save("transfer", "read-high-ack", TR(0, blksize=8, wsize=255, rsize=104857600) + TNEXT(delta=-1))
