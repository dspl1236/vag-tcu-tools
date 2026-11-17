#!/usr/bin/env python3
"""eeprom_checksum_hunt.py -- crack the SH72549 emulated-EEPROM segment checksums.

The 128 KB emulated EEPROM is 8 x 16 KB segments, each carrying TWO checksums
(community status: one of the two solved, the other open). This tool takes a real
dump and brute-tests a battery of checksum algorithms x candidate stored-field
positions x candidate covered-ranges, and reports any combination that reproduces
the stored value **across all (or most) segments**.

That multi-segment consistency is the whole point: a real algorithm reproduces the
stored checksum in EVERY segment, which rules out the coincidental single-segment
matches that make naive checksum-hunting unreliable.

No real dump yet?  `--selftest` builds a synthetic 8x16 KB EEPROM with two known
checksums and confirms the engine recovers both -- so the tool is proven before a
dump exists, and cracks the real one the moment you drop it in:

    py -3 tools/eeprom_checksum_hunt.py --selftest
    py -3 tools/eeprom_checksum_hunt.py dump_128k.bin
    py -3 tools/eeprom_checksum_hunt.py dump_128k.bin --seg-size 0x4000 --wide
"""
from __future__ import annotations

import argparse
import struct
import sys
import zlib

# --------------------------------------------------------------------------- #
#  Checksum battery.  Each entry: name -> (width_bits, fn(bytes) -> int)
# --------------------------------------------------------------------------- #

def _reflect(x: int, width: int) -> int:
    r = 0
    for _ in range(width):
        r = (r << 1) | (x & 1)
        x >>= 1
    return r

def _crc_table(width: int, poly: int, refin: bool):
    top = 1 << (width - 1)
    mask = (1 << width) - 1
    tbl = []
    for b in range(256):
        c = _reflect(b, 8) if refin else b
        c = (c << (width - 8)) & mask
        for _ in range(8):
            c = ((c << 1) ^ poly) & mask if (c & top) else (c << 1) & mask
        tbl.append(_reflect(c, width) if refin else c)
    return tbl

_CRC_CATALOG = {
    # name: (width, poly, init, refin, refout, xorout)
    "crc16_ccitt_false": (16, 0x1021, 0xFFFF, False, False, 0x0000),
    "crc16_xmodem":      (16, 0x1021, 0x0000, False, False, 0x0000),
    "crc16_aug_ccitt":   (16, 0x1021, 0x1D0F, False, False, 0x0000),
    "crc16_kermit":      (16, 0x1021, 0x0000, True,  True,  0x0000),
    "crc16_genibus":     (16, 0x1021, 0xFFFF, False, False, 0xFFFF),
    "crc16_modbus":      (16, 0x8005, 0xFFFF, True,  True,  0x0000),
    "crc16_arc":         (16, 0x8005, 0x0000, True,  True,  0x0000),
    "crc16_maxim":       (16, 0x8005, 0x0000, True,  True,  0xFFFF),
    "crc16_usb":         (16, 0x8005, 0xFFFF, True,  True,  0xFFFF),
    "crc32_bzip2":       (32, 0x04C11DB7, 0xFFFFFFFF, False, False, 0xFFFFFFFF),
    "crc32_posix":       (32, 0x04C11DB7, 0x00000000, False, False, 0xFFFFFFFF),
    "crc32_mpeg2":       (32, 0x04C11DB7, 0xFFFFFFFF, False, False, 0x00000000),
    # CRC-8 poly 0x2F = AUTOSAR SAE-J1850 "H2F" -- its table is CONFIRMED present in the ZF 8HP
    # ASW @ flash 0x46aa8 (see docs/EEPROM_RESEARCH.md). init/xorout are inferred, so cover the
    # standard H2F plus plausible variants; poly 0x2F itself is byte-exact from the image.
    "crc8_h2f":          (8, 0x2F, 0xFF, False, False, 0xFF),
    "crc8_2f_0000":      (8, 0x2F, 0x00, False, False, 0x00),
    "crc8_2f_ff00":      (8, 0x2F, 0xFF, False, False, 0x00),
    "crc8_2f_00ff":      (8, 0x2F, 0x00, False, False, 0xFF),
    "crc8_sae_j1850":    (8, 0x1D, 0xFF, False, False, 0xFF),
    "crc8_ccitt_0x07":   (8, 0x07, 0x00, False, False, 0x00),
    "crc8_maxim_0x31":   (8, 0x31, 0x00, True,  True,  0x00),
}
_CRC_TABLES = {}

def _crc(name, data):
    width, poly, init, refin, refout, xorout = _CRC_CATALOG[name]
    key = (width, poly, refin)
    tbl = _CRC_TABLES.get(key) or _CRC_TABLES.setdefault(key, _crc_table(width, poly, refin))
    mask = (1 << width) - 1
    crc = init & mask
    if refin:
        for byte in data:
            crc = (tbl[(crc ^ byte) & 0xFF] ^ (crc >> 8)) & mask
    else:
        sh = width - 8
        for byte in data:
            crc = (tbl[((crc >> sh) ^ byte) & 0xFF] ^ (crc << 8)) & mask
    if refout != refin:
        crc = _reflect(crc, width)
    return (crc ^ xorout) & mask

def _sum(data, width, endian, neg=False):
    mask = (1 << width) - 1
    step = width // 8
    if len(data) % step:
        data = data + b"\x00" * (step - len(data) % step)
    fmt = ("<" if endian == "le" else ">") + {16: "H", 32: "I"}[width] * (len(data) // step)
    s = sum(struct.unpack(fmt, data)) & mask
    return ((-s) & mask) if neg else s

def _xor(data, width, endian):
    mask = (1 << width) - 1
    step = width // 8
    if len(data) % step:
        data = data + b"\x00" * (step - len(data) % step)
    fmt = ("<" if endian == "le" else ">") + {8: "B", 16: "H", 32: "I"}[width] * (len(data) // step)
    x = 0
    for v in struct.unpack(fmt, data):
        x ^= v
    return x & mask

def _fletcher(data, width):
    if width == 16:
        s1 = s2 = 0
        for b in data:
            s1 = (s1 + b) % 255
            s2 = (s2 + s1) % 255
        return (s2 << 8) | s1
    if len(data) % 2:
        data = data + b"\x00"
    s1 = s2 = 0
    for i in range(0, len(data), 2):
        s1 = (s1 + (data[i] | (data[i + 1] << 8))) % 65535
        s2 = (s2 + s1) % 65535
    return (s2 << 16) | s1

def build_battery():
    """name -> (width_bits, fn)."""
    bat = {}
    for name in _CRC_CATALOG:
        bat[name] = (_CRC_CATALOG[name][0], lambda d, n=name: _crc(n, d))
    for w in (16, 32):
        for e in ("le", "be"):
            bat[f"sum{w}_{e}"] = (w, lambda d, w=w, e=e: _sum(d, w, e))
            bat[f"negsum{w}_{e}"] = (w, lambda d, w=w, e=e: _sum(d, w, e, neg=True))
            bat[f"xor{w}_{e}"] = (w, lambda d, w=w, e=e: _xor(d, w, e))
    bat["sum8"] = (8, lambda d: sum(d) & 0xFF)
    bat["negsum8"] = (8, lambda d: (-sum(d)) & 0xFF)
    bat["xor8"] = (8, lambda d: _xor(d, 8, "le"))
    bat["fletcher16"] = (16, lambda d: _fletcher(d, 16))
    bat["fletcher32"] = (32, lambda d: _fletcher(d, 32))
    bat["adler32"] = (32, lambda d: zlib.adler32(d) & 0xFFFFFFFF)
    bat["crc32_zlib"] = (32, lambda d: zlib.crc32(d) & 0xFFFFFFFF)
    return bat

# --------------------------------------------------------------------------- #
#  Field + range enumeration
# --------------------------------------------------------------------------- #

def read_field(seg, off, size, endian):
    return int.from_bytes(seg[off:off + size], "little" if endian == "le" else "big")

def candidate_fields(seg_size, window, wide):
    """Yield (off, size, endian) candidate stored-checksum field positions."""
    if wide:
        spots = range(seg_size)
    else:
        spots = list(range(window)) + list(range(seg_size - window, seg_size))
    for off in spots:
        for size in (1, 2, 4):          # 1 = CRC-8 (e.g. H2F) / sum8 field
            if off + size <= seg_size:
                for endian in (("le",) if size == 1 else ("le", "be")):
                    yield off, size, endian

def candidate_ranges(seg_size, fo, fs, window):
    """Byte ranges a checksum might cover.  Block-based ranges (after_hdr/
    before_ftr/core) model checksums stored in a header/footer block and
    computed over the payload between -- the common non-circular real case."""
    out = {
        "before": (0, fo),
        "after": (fo + fs, seg_size),
        "whole": (0, seg_size),                     # special: excludes the field itself
        "after_hdr": (window, seg_size),            # payload after a header cksum block
        "before_ftr": (0, seg_size - window),       # payload before a footer cksum block
        "core": (window, seg_size - window),        # payload between header & footer
    }
    res, seen = {}, set()
    for k, v in out.items():
        if v[1] <= v[0]:
            continue
        if k != "whole" and v in seen:
            continue
        seen.add(v)
        res[k] = v
    return res

def slice_range(seg, fo, fs, rname, spec):
    if rname == "whole":
        return seg[:fo] + seg[fo + fs:]
    lo, hi = spec
    return seg[lo:hi]

# --------------------------------------------------------------------------- #
#  Hunt
# --------------------------------------------------------------------------- #

def hunt(segments, seg_size, window=0x80, wide=False, min_match=None):
    battery = build_battery()
    n = len(segments)
    min_match = min_match or n
    hits = []
    for fo, fs, endian in candidate_fields(seg_size, window, wide):
        stored = [read_field(s, fo, fs, endian) for s in segments]
        if len(set(stored)) <= 1:
            continue                        # constant across segments != a checksum
        fbits = fs * 8
        for rname, rspec in candidate_ranges(seg_size, fo, fs, window).items():
            slices = [slice_range(s, fo, fs, rname, rspec) for s in segments]
            for aname, (awidth, afn) in battery.items():
                if awidth != fbits:
                    continue
                matched = 0
                for i in range(n):
                    if afn(slices[i]) == stored[i]:
                        matched += 1
                    elif matched + (n - i - 1) < min_match:
                        break               # fail-fast
                if matched >= min_match:
                    hits.append((matched, n, fo, fs, endian, rname, aname))
    hits.sort(key=lambda h: (-h[0], h[2]))
    return hits

# --------------------------------------------------------------------------- #
#  Synthetic self-test
# --------------------------------------------------------------------------- #

def _selftest():
    import random
    rng = random.Random(0xC7)
    seg_size, W = 0x4000, 0x10
    bat = build_battery()
    segs = []
    for _ in range(8):
        buf = bytearray(rng.randbytes(seg_size))
        buf[0:W] = b"\x00" * W                       # header block holds both checksums
        payload = bytes(buf[W:])                      # == range 'after_hdr'
        buf[0:4] = bat["crc32_zlib"][1](payload).to_bytes(4, "little")   # field A @ 0x0 (CRC-32)
        buf[4:8] = bat["sum32_le"][1](payload).to_bytes(4, "little")     # field B @ 0x4 (sum32)
        buf[8:9] = bytes([bat["crc8_h2f"][1](payload)])                  # field C @ 0x8 (CRC-8/0x2F)
        segs.append(bytes(buf))
    hits = hunt(segs, seg_size, window=W)
    okA = any(fo == 0 and an == "crc32_zlib" and m == n for m, n, fo, fs, en, rn, an in hits)
    okB = any(fo == 4 and an == "sum32_le" and m == n for m, n, fo, fs, en, rn, an in hits)
    okC = any(fo == 8 and fs == 1 and an == "crc8_h2f" and m == n for m, n, fo, fs, en, rn, an in hits)
    print("synthetic truth:  A=crc32_zlib@0x0  B=sum32_le@0x4  C=crc8_h2f@0x8  (all over payload [0x10:])")
    for m, n, fo, fs, en, rn, an in hits[:14]:
        print(f"  {m}/{n}  off=0x{fo:04x} size={fs} {en} range={rn:9} algo={an}")
    print(f"\nRECOVERED A (crc32@0x0): {okA}   B (sum32@0x4): {okB}   C (crc8/0x2F@0x8): {okC}")
    return 0 if (okA and okB and okC) else 1

# --------------------------------------------------------------------------- #

def main():
    ap = argparse.ArgumentParser(description="Hunt SH72549 emulated-EEPROM segment checksums.")
    ap.add_argument("dump", nargs="?", help="128 KB EEPROM dump")
    ap.add_argument("--seg-size", default="0x4000", help="segment size (default 0x4000 = 16 KB)")
    ap.add_argument("--window", default="0x80", help="header/footer scan window (default 0x80)")
    ap.add_argument("--wide", action="store_true", help="scan every 2-byte offset for the field (slow)")
    ap.add_argument("--min-match", type=int, default=0, help="min segments that must match (0 = all)")
    ap.add_argument("--selftest", action="store_true", help="validate the engine on a synthetic EEPROM")
    a = ap.parse_args()

    if a.selftest:
        sys.exit(_selftest())
    if not a.dump:
        ap.error("supply a dump, or run --selftest")

    with open(a.dump, "rb") as fh:
        data = fh.read()
    seg_size = int(a.seg_size, 0)
    segs = [data[i:i + seg_size] for i in range(0, len(data), seg_size)]
    segs = [s for s in segs if len(s) == seg_size]
    print(f"dump {len(data):,} B -> {len(segs)} x {seg_size} B segments")
    hits = hunt(segs, seg_size, window=int(a.window, 0), wide=a.wide,
                min_match=(a.min_match or None))
    if not hits:
        print("\nNo algorithm reproduced a stored field across the required segments.")
        print("Try --wide (scan all offsets) or --min-match to relax; or the scheme is")
        print("non-trivial (seeded/sub-range/chained CRC) -> RE the ASW routine instead.")
        return
    print(f"\n{len(hits)} candidate checksum(s) (most segments first):")
    for m, n, fo, fs, en, rn, an in hits[:40]:
        print(f"  {m}/{n} seg  field@0x{fo:04x} {fs}B {en}  range={rn:9}  algo={an}")
    full = [h for h in hits if h[0] == h[1]]
    if full:
        print(f"\n{len(full)} reproduce ALL segments -> the real checksums:")
        for m, n, fo, fs, en, rn, an in full:
            print(f"  field@0x{fo:04x} {fs}B {en}  = {an} over {rn}")


if __name__ == "__main__":
    main()
