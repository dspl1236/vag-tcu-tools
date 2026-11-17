#!/usr/bin/env python3
"""Recover or import the AES-128-CBC firmware key for a key-unknown VAG TCU.

The key is NOT derivable from the flashdaten: AES-128 can't be brute-forced, and
the FRF carries no plaintext BOOT. It lives in the chip's BOOT block in plaintext
-- for DQ381 at flash 0x010544 (IV) / 0x010554 (key), i.e. decoded-BOOT offset
0x344 / 0x354. Read 32 bytes from one real TCU (OBD ReadMemoryByAddress 0x23 after
an SA2 unlock, or a bench boot-mode SCI read), then import it here.

Modes:
  extract   --boot-dump BOOT.bin [--frf F]   pull the key/IV at the known offset
  scan      --boot-dump BOOT.bin --frf F      locate the key/IV anywhere in a dump
  validate  --frf F --key HEX --iv HEX        confirm a key/IV decrypts the FRF
  sweep     --frf F                           test every known VW Group key

`validate`/`scan`/`sweep` confirm a key by decrypting the real update file and
checking every block decompresses to its exact declared size.
"""
import argparse
import sys
import xml.etree.ElementTree as ET
from binascii import unhexlify
from io import BytesIO
from pathlib import Path
from zipfile import ZipFile

from Crypto.Cipher import AES

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from core.crypto_aes import AESBlockCrypto
from core.frf import decrypt_frf, load_frf_key
from core.odx import extract_frf_blocks
from platforms.dq381 import extract_boot_key

MAGIC = bytes.fromhex("876543")  # LZSS10 literal header, just after the 0x00 flag

KNOWN_KEYS = {
    "DQ381_BL301": ("000102030405060708090A0B0C0D0E0F", "101112131415161718191A1B1C1D1E1F"),
    "Simos12": ("314d7536416e3047396a413252356f45", "306e37426b6b536f316d4a6974366d34"),
    "Simos12.2": ("41326D3F50613D306C4C36616E346721", "70493465726345296470557333235379"),
    "Simos16": ("0ACFFB513E95644A396A41325235D9A9", "01D137426B6B536FB3333F691B366D34"),
    "Simos18": ("98D31202E48E3854F2CA561545BA6F2F", "E7861278C508532798BCA4FE451D20D1"),
    "Simos18.10": ("AE540502E48E3854DBCA1A1545BA6F33", "62F313FA5C08532798BCA452471D20D5"),
    "Simos18.41": ("6E3FE03619F138798CB4ECDCC762005F", "000102030405060708090A0B0C0D0E0F"),
}


def _largest_aa_block(frf_path):
    """(id, raw_ciphertext, uncompressed_size) of the largest AES (method-AA) block."""
    dec = decrypt_frf(load_frf_key(None), Path(frf_path).read_bytes())
    zf = ZipFile(BytesIO(dec))
    odx = odxf = None
    bins = {}
    for name in zf.namelist():
        low = name.lower()
        if low.endswith(".odx-f"):
            odxf = name
        elif low.endswith(".odx"):
            odx = name
        elif low.endswith(".bin"):
            bins[name] = zf.read(name)
    root = ET.fromstring(zf.read(odx or odxf).decode("utf-8", "replace"))
    best = None
    for fd in root.findall(".//FLASHDATA"):
        if fd.findtext("ENCRYPT-COMPRESS-METHOD", "") != "AA":
            continue
        de = fd.findall("./DATA")
        if de and de[0].text:
            raw = unhexlify(de[0].text.strip())
        else:
            raw = bins.get(fd.findtext("DATAFILE", "").strip())
        if raw and (best is None or len(raw) > len(best[1])):
            fid = fd.get("ID", "?")
            seg = root.findall(
                f".//DATABLOCK/FLASHDATA-REF[@ID-REF='{fid}']"
                f"/../SEGMENTS/SEGMENT/UNCOMPRESSED-SIZE"
            )
            best = (fid, raw, int(seg[0].text) if seg else 0)
    if best is None:
        raise ValueError("no AES (method-AA) block found in this FRF")
    return best


def _looks_like_lzss10(plaintext):
    """True if an AES plaintext opens like an LZSS10 stream (876543 magic)."""
    return plaintext[1:4] == MAGIC or MAGIC in plaintext[:64]


def _snippet(key, iv):
    return (
        "\n# --- paste into the platform config (platforms/<name>/__init__.py) ---\n"
        f'KEY = bytes.fromhex("{key.hex()}")\n'
        f'IV = bytes.fromhex("{iv.hex()}")\n'
        "CRYPTO = AESBlockCrypto(KEY, IV)\n"
    )


def _report(frf_path, key, iv):
    """Full validation: decrypt the whole FRF and confirm every block decodes."""
    blocks = extract_frf_blocks(frf_path, crypto=AESBlockCrypto(key, iv))
    failed = [k for k in blocks if k.endswith(".encrypted")]
    carries = any(key in bytes(v) and iv in bytes(v) for v in blocks.values())
    print(f"\nValidation against {Path(frf_path).name}:")
    for k, v in blocks.items():
        flag = "  <-- FAILED (undecoded)" if k.endswith(".encrypted") else ""
        print(f"  {k.split('.')[-1]}: {len(v):,} bytes{flag}")
    print(f"  all blocks decoded : {not failed}")
    print(f"  BOOT carries key/IV: {carries}")
    if not failed:
        print("\n*** KEY CONFIRMED ***")
        print(f"  Key: {key.hex()}\n  IV:  {iv.hex()}")
        print(_snippet(key, iv))
        return True
    print("\nThis key did NOT decrypt the FRF — wrong key/IV, or wrong FRF for this TCU.")
    return False


def do_extract(args):
    dump = Path(args.boot_dump).read_bytes()
    key, iv = extract_boot_key(dump, base=args.base)
    print(f"IV  (flash {args.base + (0x010544 - 0x010200):#08x}): {iv.hex()}")
    print(f"Key (flash {args.base + (0x010554 - 0x010200):#08x}): {key.hex()}")
    if args.frf:
        return _report(args.frf, key, iv)
    print(_snippet(key, iv))
    print("Pass --frf FILE to confirm this key against a real update file.")
    return True


def do_validate(args):
    return _report(args.frf, bytes.fromhex(args.key), bytes.fromhex(args.iv))


def do_scan(args):
    dump = Path(args.boot_dump).read_bytes()
    fid, cipher, _size = _largest_aa_block(args.frf)
    head = cipher[:48]
    print(f"scanning {len(dump):,}-byte dump vs {fid.split('.')[-1]} (step {args.step}) ...")
    for off in range(0, len(dump) - 32, args.step):
        iv = dump[off:off + 16]
        key = dump[off + 16:off + 32]
        if _looks_like_lzss10(AES.new(key, AES.MODE_CBC, iv).decrypt(head)):
            print(f"\ncandidate at dump offset {off:#x} (iv) / {off + 16:#x} (key)")
            if _report(args.frf, key, iv):
                return True
    print("\nno key/IV in this dump decrypts the FRF (wrong dump, or key is stored transformed)")
    return False


def do_sweep(args):
    fid, cipher, _size = _largest_aa_block(args.frf)
    head = cipher[:48]
    print(f"block {fid.split('.')[-1]}  cipher head {cipher[:16].hex()}")
    extra = [bytes(16), bytes(range(0x10, 0x20)), bytes([0xFF] * 16)]
    for name, (kh, ivh) in KNOWN_KEYS.items():
        key = bytes.fromhex(kh)
        for iv in {bytes.fromhex(ivh), *extra, key}:
            if _looks_like_lzss10(AES.new(key, AES.MODE_CBC, iv).decrypt(head)):
                print(f"\n*** HIT {name} ***")
                return _report(args.frf, key, iv)
    print("no known VW Group key decrypts this block — the TCU uses a non-default key")
    return False


def _hexint(value):
    return int(value, 0)


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    sub = parser.add_subparsers(dest="mode", required=True)

    pe = sub.add_parser("extract", help="pull the key/IV from a plaintext BOOT dump")
    pe.add_argument("--boot-dump", required=True)
    pe.add_argument("--base", type=_hexint, default=0x010200,
                    help="flash address the dump starts at (default 0x010200)")
    pe.add_argument("--frf", help="optionally confirm against this update file")
    pe.set_defaults(func=do_extract)

    ps = sub.add_parser("scan", help="locate the key/IV anywhere in a BOOT dump")
    ps.add_argument("--boot-dump", required=True)
    ps.add_argument("--frf", required=True)
    ps.add_argument("--step", type=_hexint, default=1)
    ps.set_defaults(func=do_scan)

    pv = sub.add_parser("validate", help="confirm a key/IV decrypts an FRF")
    pv.add_argument("--frf", required=True)
    pv.add_argument("--key", required=True)
    pv.add_argument("--iv", required=True)
    pv.set_defaults(func=do_validate)

    pw = sub.add_parser("sweep", help="test all known VW Group keys against an FRF")
    pw.add_argument("--frf", required=True)
    pw.set_defaults(func=do_sweep)

    args = parser.parse_args()
    sys.exit(0 if args.func(args) else 1)


if __name__ == "__main__":
    main()
