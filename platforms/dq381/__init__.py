"""DQ381.2 / ALx52 platform configuration.

Bosch TCU on Renesas SH72549 (SH-2A, big-endian).
Vehicles: MK8 GTI, Golf R, 8Y A3/S3, Tiguan, Cupra Formentor.
"""

from core.crypto_aes import AESBlockCrypto

# --- BL301 Crypto ---
BL301_KEY = bytes(range(0x10))  # 000102030405060708090A0B0C0D0E0F
BL301_IV = bytes(range(0x10, 0x20))   # 101112131415161718191A1B1C1D1E1F
BL301_CRYPTO = AESBlockCrypto(BL301_KEY, BL301_IV)

# BL401 key: UNKNOWN — stored at BOOT offset 0x344 (IV) / 0x354 (Key)
# flash address 0x010544 (IV) / 0x010554 (Key)
# 32-byte read from any physical BL401 TCU recovers it.
BL401_CRYPTO = None

# Where the AES key/IV sit in a plaintext BOOT read (BL301 and BL401 share this).
BOOT_KEY_BASE = 0x010200   # BOOT block flash base
IV_FLASH = 0x010544        # IV,  16 bytes
KEY_FLASH = 0x010554       # key, 16 bytes


def extract_boot_key(boot_dump, base=BOOT_KEY_BASE):
    """Pull (key, iv) out of a plaintext BOOT dump (DQ381 layout).

    `base` is the flash address the dump starts at — the BOOT block base by
    default, or the actual start of an arbitrary flash read (e.g. a 32-byte read
    at 0x010544). Returns (key, iv), 16 bytes each; raises ValueError if the
    offsets fall outside the dump.
    """
    iv_off = IV_FLASH - base
    key_off = KEY_FLASH - base
    if not (0 <= iv_off <= len(boot_dump) - 16 and 0 <= key_off <= len(boot_dump) - 16):
        raise ValueError(
            f"key/IV offset outside a {len(boot_dump):#x}-byte dump "
            f"(iv@{iv_off:#x}, key@{key_off:#x}); check `base`"
        )
    return bytes(boot_dump[key_off:key_off + 16]), bytes(boot_dump[iv_off:iv_off + 16])

# --- SA2 Scripts ---
SA2_BL301 = bytes.fromhex("6806814A05876B5F7DD5494C")
SA2_BL401 = bytes.fromhex(
    "9390783612680B814A07872956814F6B05876BEE2005828490783612494C")

# --- Flash Layout (BL301) ---
FLASH_LAYOUT = {
    "BOOT": {"base": 0x010200, "size": 0x01FE00},
    "ASW":  {"base": 0x030200, "size": 0x10FE00},
    "CAL":  {"base": 0x140200, "size": 0x03FE00},
}

# --- CAN IDs ---
CAN_TX = 0x7E1
CAN_RX = 0x7E9

# --- Part Number Variants ---
# 555 = FWD, 556 = AWD, 557 = R/S
VARIANTS = {
    "0GC906555": "FWD",
    "0GC906556": "AWD",
    "0GC906557": "R/S",
}

# --- Confirmed CAL Addresses (BL301, from cross-variant analysis) ---
CAL_ADDRESSES = {
    "torque_cap_drive":     0x28138,
    "torque_cap_sport":     0x32138,
    "clutch_map_drive":     0x20A80,
    "clutch_map_sport":     0x2AA80,
    "rev_limiter_primary":  0x0333A,
    "rev_limiter_secondary": 0x04B66,
    "per_gear_rev_limits":  0x27CF8,
    "shift_schedule_axes":  0x068B0,
    "launch_rpm":           0x1CC46,
    "launch_torque":        0x1C3E6,
    "speed_limiter":        0x04E4E,
    "torque_axis":          0x018B4,
    "cal_id_string":        0x00100,
    "hw_part_number":       0x019D2,
    "platform_id":          0x019F0,
}
