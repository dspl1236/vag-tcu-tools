"""Checksum validation and correction for VAG flash blocks.

DQ381: CRC32 (zlib) at CAL offset 0x44, range pointers at 0x38/0x3C.
ZF 8HP: CRC-CCITT at block-specific offsets.
DQ381 EEPROM (Renesas EEL): 32-bit big-endian word-sum of the data region,
    stored big-endian at block offset 0x50.
"""

import struct
import zlib


def crc32_validate(data: bytes, crc_offset: int = 0x44,
                   range_start_offset: int = 0x38,
                   range_end_offset: int = 0x3C,
                   block_base: int = 0x140200) -> tuple[bool, int, int]:
    """Validate CRC32 checksum in a DQ381 CAL block.

    Returns:
        (valid, stored_crc, computed_crc)
    """
    stored = struct.unpack_from(">I", data, crc_offset)[0]
    range_start = struct.unpack_from(">I", data, range_start_offset)[0] - block_base
    range_end = struct.unpack_from(">I", data, range_end_offset)[0] - block_base

    region = bytearray(data[range_start:range_end + 1])
    # Zero the CRC cell only when it lies inside the CRC'd range. On DQ381 CAL
    # blocks the cell (0x44) sits *before* the range (e.g. 0x100..), so it is
    # not part of the CRC and must be left untouched -- not zeroed via a
    # negative region index, which would corrupt the tail of the region.
    cell = crc_offset - range_start
    if 0 <= cell <= len(region) - 4:
        for i in range(4):
            region[cell + i] = 0x00

    computed = zlib.crc32(bytes(region)) & 0xFFFFFFFF
    return (stored == computed, stored, computed)


def crc32_fix(data: bytearray, crc_offset: int = 0x44,
              range_start_offset: int = 0x38,
              range_end_offset: int = 0x3C,
              block_base: int = 0x140200) -> bytearray:
    """Recompute and patch CRC32 in a DQ381 CAL block."""
    result = bytearray(data)
    range_start = struct.unpack_from(">I", data, range_start_offset)[0] - block_base
    range_end = struct.unpack_from(">I", data, range_end_offset)[0] - block_base

    for i in range(4):
        result[crc_offset + i] = 0x00

    region = result[range_start:range_end + 1]
    computed = zlib.crc32(bytes(region)) & 0xFFFFFFFF
    struct.pack_into(">I", result, crc_offset, computed)
    return result


# --- DQ381 emulated-EEPROM (Renesas EEL ring) data checksum ------------------
#
# The 128 KB data flash is a wear-levelled ring of 8 x 16 KB copies of one
# logical block. Each live copy's header:
#   0x00  u32  EEL status word (0x4001007c on a live block)
#   0x04  u32  data size, big-endian (0x21b4 on the DQ381 units seen)
#   0x08  u32  write counter, big-endian (newest copy wins)
#   0x0c  ...  SW tag ("d13716")
#   0x50  u32  DATA CHECKSUM, big-endian            <-- recomputed here
#   0x54  u16  EEL management/wear state (NOT a data checksum; payload-independent)
#   0x56  u16  0xffff (erased/constant)
#   0x80  ..   user data, `size` bytes
#
# The data checksum is a plain 32-bit big-endian word-sum of the data region,
# reproduced byte-exact across every live block of real DQ381 dumps. The 16-bit
# value historically reported at 0x52 is simply this sum's low word; the "second
# checksum" sought by the community is its upper half -- a correcting tool must
# rewrite all four bytes 0x50-0x53, not just 0x52-0x53. The 0x54 word is EEL
# bookkeeping that tracks the ring counter, is independent of the payload, and is
# left untouched when editing data in place.

EEL_BLOCK_SIZE = 0x4000      # 16 KB per ring copy


def eel_word_sum32(data: bytes) -> int:
    """32-bit sum of big-endian u16 words over `data` (odd tail byte padded high)."""
    total = 0
    n = len(data)
    for i in range(0, n - (n & 1), 2):
        total += (data[i] << 8) | data[i + 1]
    if n & 1:
        total += data[n - 1] << 8
    return total & 0xFFFFFFFF


def eel_eeprom_validate(block: bytes, cksum_offset: int = 0x50,
                        size_offset: int = 0x04,
                        data_offset: int = 0x80) -> tuple[bool, int, int]:
    """Validate the DQ381 EEL block data checksum (32-bit BE word-sum).

    `block` is one 16 KB ring copy.

    Returns:
        (valid, stored, computed)
    """
    size = struct.unpack_from(">I", block, size_offset)[0]
    stored = struct.unpack_from(">I", block, cksum_offset)[0]
    computed = eel_word_sum32(block[data_offset:data_offset + size])
    return (stored == computed, stored, computed)


def eel_eeprom_fix(block: bytearray, cksum_offset: int = 0x50,
                   size_offset: int = 0x04,
                   data_offset: int = 0x80) -> bytearray:
    """Recompute and patch the DQ381 EEL block data checksum.

    Only the 32-bit sum at `cksum_offset` is rewritten; the EEL management word
    at 0x54 is payload-independent and intentionally left as-is.
    """
    result = bytearray(block)
    size = struct.unpack_from(">I", result, size_offset)[0]
    computed = eel_word_sum32(result[data_offset:data_offset + size])
    struct.pack_into(">I", result, cksum_offset, computed)
    return result
