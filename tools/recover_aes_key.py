#!/usr/bin/env python3
"""AES-128-CBC key recovery from known plaintext + ciphertext.

Given a raw flash dump (plaintext) and the matching encrypted FRF
block (ciphertext), verifies candidate keys and recovers the AES
key/IV pair.

Usage:
    python recover_aes_key.py --plaintext dump.bin --ciphertext encrypted.bin

How it works:
    AES-CBC: P[0] = AES_block_decrypt(C[0], K) XOR IV
    Given (P, C), we try all known VW Group keys + common IV patterns.
    If none match, the raw dump is still useful for direct firmware
    analysis — just can't derive AES-128 keys from math alone.
"""

import argparse
from pathlib import Path
from Crypto.Cipher import AES


KNOWN_KEYS = {
    "DQ381_BL301":  ("000102030405060708090A0B0C0D0E0F",
                     "101112131415161718191A1B1C1D1E1F"),
    "Simos12":      ("314d7536416e3047396a413252356f45",
                     "306e37426b6b536f316d4a6974366d34"),
    "Simos12.2":    ("41326D3F50613D306C4C36616E346721",
                     "70493465726345296470557333235379"),
    "Simos16":      ("0ACFFB513E95644A396A41325235D9A9",
                     "01D137426B6B536FB3333F691B366D34"),
    "Simos18":      ("98D31202E48E3854F2CA561545BA6F2F",
                     "E7861278C508532798BCA4FE451D20D1"),
    "Simos18.10":   ("AE540502E48E3854DBCA1A1545BA6F33",
                     "62F313FA5C08532798BCA452471D20D5"),
    "Simos18.41":   ("6E3FE03619F138798CB4ECDCC762005F",
                     "000102030405060708090A0B0C0D0E0F"),
}


def try_known_keys(plaintext: bytes, ciphertext: bytes):
    """Try all known VW Group AES keys."""
    for name, (k_hex, iv_hex) in KNOWN_KEYS.items():
        key = bytes.fromhex(k_hex)
        iv = bytes.fromhex(iv_hex)
        cipher = AES.new(key, AES.MODE_CBC, iv=iv)
        test = cipher.decrypt(ciphertext[:48])
        if test[:32] == plaintext[:32]:
            return name, key, iv
    return None


def try_iv_patterns(plaintext: bytes, ciphertext: bytes):
    """Given (P, C), try common IV patterns with each known key.
    
    Also tries: if first 16 bytes of ciphertext are an IV prefix,
    skip them and treat byte 16 onward as ciphertext block 0.
    """
    ivs = {
        "null":     bytes(16),
        "seq_0F":   bytes(range(16)),
        "seq_1F":   bytes(range(0x10, 0x20)),
        "all_FF":   bytes([0xFF] * 16),
    }
    
    for k_name, (k_hex, _) in KNOWN_KEYS.items():
        key = bytes.fromhex(k_hex)
        for iv_name, iv in ivs.items():
            cipher = AES.new(key, AES.MODE_CBC, iv=iv)
            test = cipher.decrypt(ciphertext[:48])
            if test[:32] == plaintext[:32]:
                return f"{k_name}+{iv_name}", key, iv
    
    # Try with 16-byte IV prepended to ciphertext
    if len(ciphertext) > 32:
        iv_prefix = ciphertext[:16]
        ct_body = ciphertext[16:]
        for k_name, (k_hex, _) in KNOWN_KEYS.items():
            key = bytes.fromhex(k_hex)
            cipher = AES.new(key, AES.MODE_CBC, iv=iv_prefix)
            test = cipher.decrypt(ct_body[:48])
            if test[:32] == plaintext[:32]:
                return f"{k_name}+prepended_IV", key, iv_prefix

    return None


def main():
    parser = argparse.ArgumentParser(description="AES key recovery tool")
    parser.add_argument("--plaintext", required=True,
                        help="Raw flash dump .bin (decrypted)")
    parser.add_argument("--ciphertext", required=True,
                        help="Encrypted block from FRF extraction")
    args = parser.parse_args()

    pt = Path(args.plaintext).read_bytes()
    ct = Path(args.ciphertext).read_bytes()
    print(f"Plaintext:  {len(pt):>10,} bytes")
    print(f"Ciphertext: {len(ct):>10,} bytes")

    # Size check
    if len(pt) != len(ct):
        print("\n⚠  Size mismatch — files may not correspond")
        print(f"   Trying with min({len(pt):,}, {len(ct):,}) bytes")

    min_len = min(len(pt), len(ct))
    pt = pt[:min_len]
    ct = ct[:min_len]

    print("\n--- Trying known VW Group keys ---")
    result = try_known_keys(pt, ct)
    if result:
        name, key, iv = result
        print(f"\n✓ KEY FOUND: {name}")
        print(f"  Key: {key.hex()}")
        print(f"  IV:  {iv.hex()}")
        return

    print("  No direct match.")

    print("\n--- Trying IV pattern variations ---")
    result = try_iv_patterns(pt, ct)
    if result:
        name, key, iv = result
        print(f"\n✓ KEY FOUND: {name}")
        print(f"  Key: {key.hex()}")
        print(f"  IV:  {iv.hex()}")
        return

    print("  No match with known keys + IV patterns.")
    print("\n✗ AES-128 key is not among known VW Group keys.")
    print("  The raw dump is still valuable for direct firmware analysis.")
    print("  When a candidate key surfaces, rerun this tool to verify.")


if __name__ == "__main__":
    main()
