"""LZSS decompression — 1023-byte sliding window (flag bit set = literal).

Big-endian: 6-bit count + 10-bit displacement.  Based on bri3d/VW_Flash (MIT).

NOTE: DQ381 flash blocks are ODX method 0xAA (AES + compression).  After AES they
decode to an INVERTED-flag stream (flag 0x00 = literal, 876543 magic) that this
non-inverted decoder does not handle; the exact DQ381 AA framing is not yet
pinned (see docs/PLATFORM_RESEARCH.md).
"""


def decompress_lzss(data: bytes, output_size: int = 0) -> bytearray:
    """Decompress LZSS data with 1023-byte window (DQ381 variant).

    Args:
        data: Compressed input bytes.
        output_size: Expected output size (0 = decompress until input exhausted).

    Returns:
        Decompressed bytearray.
    """
    output = bytearray()
    i = 0
    while i < len(data):
        flag = data[i]
        i += 1
        for bit in range(8):
            if i >= len(data):
                break
            if output_size and len(output) >= output_size:
                return output[:output_size]
            if flag & (1 << (7 - bit)):
                output.append(data[i])
                i += 1
            else:
                if i + 1 >= len(data):
                    break
                b0 = data[i]
                b1 = data[i + 1]
                i += 2
                count = (b0 >> 2) + 3
                displacement = ((b0 & 0x03) << 8) | b1
                if displacement == 0:
                    displacement = 1
                if displacement > len(output):
                    raise ValueError(
                        f"LZSS stream corrupt: displacement {displacement} "
                        f"exceeds {len(output)} bytes decoded "
                        f"(wrong key, or data is not this LZSS variant)"
                    )
                start = len(output) - displacement
                for j in range(count):
                    output.append(output[start + j])
    if output_size:
        return output[:output_size]
    return output
