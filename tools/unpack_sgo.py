#!/usr/bin/env python3
"""Unpack a VAG SGML Object File (.sgo) transmission container.

SGO "format 0" blocks are container XOR-0xFF plaintext; "format 1" blocks use a
family substitution cipher (the recovered tables in platforms/sgo_tables.py).
A method label alone cannot always pick the family, so pass --family.

Modes:
  info     FILE                          header + block map
  families                               list known cipher families
  unpack   FILE --family F [--out DIR]   decode every block (writes DIR if given)

Build the optional C accelerator first (`python -m core.build_sgo_fast`) for a
large speed-up on big blocks; it is not required.
"""
import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from core.sgo import parse_sgo
from platforms.sgo_tables import FAMILIES, crypto_for


def do_info(args):
    print(parse_sgo(args.file).summary())
    return True


def do_families(args):
    width = max(len(k) for k in FAMILIES)
    print(f"  {'family':<{width}}  {'mode':<11}  description")
    for name in sorted(FAMILIES):
        _table, mode, desc = FAMILIES[name]
        print(f"  {name:<{width}}  {mode:<11}  {desc}")
    return True


def do_unpack(args):
    sgo = parse_sgo(args.file)
    crypto = crypto_for(args.family) if args.family else None
    out_dir = Path(args.out) if args.out else None
    if out_dir:
        out_dir.mkdir(parents=True, exist_ok=True)
    print(sgo.summary())
    print()
    ok = True
    for i, block in enumerate(sgo.blocks):
        try:
            data = sgo.decode_block(i, crypto=crypto)
        except ValueError as exc:
            ok = False
            print(f"  [{i}] FAILED: {exc}")
            continue
        name = f"block{i:02d}_{block['id_be']:#08x}_fmt{block['format']}.bin"
        if out_dir:
            (out_dir / name).write_bytes(data)
            print(f"  [{i}] {len(data):,} bytes -> {out_dir / name}")
        else:
            print(f"  [{i}] {len(data):,} bytes ({name}) — pass --out DIR to write")
    return ok


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    sub = parser.add_subparsers(dest="mode", required=True)

    pi = sub.add_parser("info", help="print the SGO header + block map")
    pi.add_argument("file")
    pi.set_defaults(func=do_info)

    pf = sub.add_parser("families", help="list known cipher families")
    pf.set_defaults(func=do_families)

    pu = sub.add_parser("unpack", help="decode blocks (optionally to --out DIR)")
    pu.add_argument("file")
    pu.add_argument("--family", help="cipher family for format-1 blocks (see `families`)")
    pu.add_argument("--out", help="directory to write decoded blocks into")
    pu.set_defaults(func=do_unpack)

    args = parser.parse_args()
    sys.exit(0 if args.func(args) else 1)


if __name__ == "__main__":
    main()
