"""ZF 8HP (AL551/AL552) platform configuration.

ZF TCU on Renesas SH72549 (SH-2A, big-endian).
Vehicles: Audi A6/A7 C7, A8 D4, Q5 8R, A4/A5 B9.

Encryption: Method 0x22 — 19-byte repeating XOR + LZZ compression.
Key: CyA2008ZFVAGtcuxsam (CRACKED, verified)

Note: 8K0927155 (A4/A5 B8) is NOT ZF 8HP — it is VL381 Multitronic CVT
on TriCore TC1766, a completely different platform.
"""

from core.crypto_xor import XORBlockCrypto

# --- Method 0x22 Crypto (XOR + LZZ) ---
# Key: 19-byte repeating XOR, ASCII "CyA2008ZFVAGtcuxsam"
# Verified on 4G0927158BE (A6/A7 C7) and 4H1927158AD (A8 D4).
XOR_KEY = b"CyA2008ZFVAGtcuxsam"
XOR_CRYPTO = XORBlockCrypto(XOR_KEY)

# --- SA2 Scripts ---
SA2_4G0 = bytes.fromhex(
    "6802814993A55A55AA4A05878105952668058249845AA5AA558703F7805C4C")
SA2_SIMOS_SUITE = bytes.fromhex(
    "6805824A10680284100819734A05872506200382499318111973824A058712082001824A0181494C")

# --- Memory Map (from A2L, AL551 Gen2) ---
# Source: projectLSaudiA4, NefMoto Dec 2024
MEMORY_MAP = {
    "BOOT":     {"start": 0x000000, "size": 0x040000},
    "ASW":      {"start": 0x040080, "size": 0x13FAF0},
    "CAL_HDR":  {"start": 0x180000, "size": 0x000280},
    "CAL_CODE": {"start": 0x180280, "size": 0x00FD80},
    "CAL_DATA": {"start": 0x190000, "size": 0x06FD60},
}

# CAL checksum: CRC32 over 0x190000-0x1FFD5F, stored at 0x180244
CAL_CRC_OFFSET = 0x180244
CAL_CRC_RANGE = (0x190000, 0x1FFD5F)

# --- CAN IDs ---
CAN_TX = 0x7E1
CAN_RX = 0x7E9

# --- Part Number Families ---
FAMILIES = {
    "4G0927158": "A6/A7 C7 AL551 (8HP55)",    # method 0x22, CONFIRMED
    "4H1927158": "A8 D4 ALX51 (8HP90)",        # method 0x22, CONFIRMED
    "8R0927156": "Q5 8R (8HP55)",              # unverified method
    "8W0927155": "A4/A5 B9 (8HP55)",           # unverified method
    "4K0927153": "A6/A7 C8 (8HP51)",           # unverified method
    "4M0927158": "Q7/Q8 4M (8HP)",             # unverified method
}

# NOT ZF 8HP — confirmed different platforms:
# "8K0927155" = VL381 Multitronic CVT (TriCore TC1766, method 0x01)
#   ODX identifies as EV_TCMVL381_A01, NOT ZF 8HP
#   Same platform as DL501 (TriCore, trivial AES key at ~0x05F000)

# --- ZF 8HP Variants (all SH72549) ---
ZF_VARIANTS = {
    "8HP45": {"torque": 450, "vehicles": "BMW 1/2/3/4/5, Alpina"},
    "8HP50": {"torque": 500, "vehicles": "BMW, Alfa Romeo"},
    "8HP55": {"torque": 550, "vehicles": "BMW, Audi A4-A8"},
    "8HP70": {"torque": 700, "vehicles": "BMW 5/7, Dodge Ram, Jeep, Maserati"},
    "8HP75": {"torque": 750, "vehicles": "Alfa Romeo, BMW"},
    "8HP90": {"torque": 900, "vehicles": "BMW 7, Rolls Royce"},
}
