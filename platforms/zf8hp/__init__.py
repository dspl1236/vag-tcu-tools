"""ZF 8HP (AL551/ALX510/ALX520) platform configuration.

ZF TCU on Renesas SH72549 (SH-2A, big-endian).
Gen3 (post-2020) moved to Infineon TC275 TriCore — not covered here.

Two encryption schemes exist on SH72549:
  - Method 0x22 (XOR + LZZ): 4G0, 4H1 families — CRACKED
  - Method 0xAA (AES-CBC + LZSS): 4M0 family — key UNKNOWN

Confirmed vehicles:
  4G0927158 — A6/A7 C7 (AL551/8HP55), method 0x22
  4H1927158 — A8 D4 (ALX510/8HP90), method 0x22
  4M0927158 — Q7/Q8 4M (ALX520/8HP), method 0xAA

Note: Many Audi transmission part numbers are NOT ZF 8HP:
  8K0927155 = VL381 Multitronic CVT (TriCore TC1766)
  8R0927156 = DL501 S-Tronic 7-speed (EV_TCMDL501)
  8W0927155 = DL-382 7-speed (EV_TCMDL382021)
  4K0927153 = DL-382 7-speed (EV_TCMDL382021)
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
    "4G0927158": "A6/A7 C7 AL551 (8HP55)",    # method 0x22 XOR, CONFIRMED
    "4H1927158": "A8 D4 ALX51 (8HP90)",        # method 0x22 XOR, CONFIRMED
    "4M0927158": "Q7/Q8 4M ALX520 (8HP)",      # method 0xAA AES, key UNKNOWN
}

# NOT ZF 8HP — confirmed different platforms:
# "8K0927155" = VL381 Multitronic CVT (TriCore TC1766, method 0x01)
# "8R0927156" = DL501 S-Tronic 7-speed (EV_TCMDL501, method 0x11)
# "8W0927155" = DL-382 7-speed (EV_TCMDL382021, method 0x11)
# "4K0927153" = DL-382 7-speed (EV_TCMDL382021, method 0x1A)
# "4M0927158" 0xAA variant = same SH72549 MCU, newer bootloader with AES

# --- ZF 8HP Variants (all SH72549) ---
ZF_VARIANTS = {
    "8HP45": {"torque": 450, "vehicles": "BMW 1/2/3/4/5, Alpina"},
    "8HP50": {"torque": 500, "vehicles": "BMW, Alfa Romeo"},
    "8HP55": {"torque": 550, "vehicles": "BMW, Audi A4-A8"},
    "8HP70": {"torque": 700, "vehicles": "BMW 5/7, Dodge Ram, Jeep, Maserati"},
    "8HP75": {"torque": 750, "vehicles": "Alfa Romeo, BMW"},
    "8HP90": {"torque": 900, "vehicles": "BMW 7, Rolls Royce"},
}
