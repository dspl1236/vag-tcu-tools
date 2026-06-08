"""Checksum validation and correction for VAG flash blocks.

DQ381: CRC32 (zlib) at CAL offset 0x44, range pointers at 0x38/0x3C.
ZF 8HP: CRC-CCITT at block-specific offsets.
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
    for i in range(4):
        region[crc_offset - range_start + i] = 0x00

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
