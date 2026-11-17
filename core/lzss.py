"""LZSS decompression — VW_Flash "LZSS10", 1023-byte sliding window.

Inverted flags (flag bit 0 = literal, 1 = back-reference), MSB-first.  Each
back-reference is a big-endian 16-bit word: 6-bit count (raw) + 10-bit
displacement.  This is the format DQ381 flash blocks (ODX method 0xAA) decode to
after AES — confirmed byte-exact on real 2024 flashdaten: the decoded BOOT block
carries the AES IV/key at their documented offsets (0x344 / 0x354), and every
block decodes to its exact declared size.

Based on bri3d/VW_Flash (MIT); cross-checked against lsdlsd88/TCU-FRF-SGO-UNPACKER.
"""


def decompress_lzss(data: bytes, output_size: int = 0) -> bytearray:
    """Decompress VW_Flash LZSS10 (inverted flags, 6-bit count + 10-bit window).

    Args:
        data: Compressed input bytes.
        output_size: Expected output size (0 = decompress until input exhausted).

    Returns:
        Decompressed bytearray.

    Raises:
        ValueError: on a back-reference whose displacement points before the
            start of the output (corrupt stream, or wrong decryption key).
    """
    output = bytearray()
    i = 0
    while i < len(data):
        if output_size and len(output) >= output_size:
            break
        flag = data[i]
        i += 1
        for bit in range(8):
            if i >= len(data):
                break
            if output_size and len(output) >= output_size:
                break
            if not (flag >> (7 - bit)) & 1:          # 0 = literal
                output.append(data[i])
                i += 1
            else:                                     # 1 = back-reference
                if i + 1 >= len(data):
                    break
                word = (data[i] << 8) | data[i + 1]
                i += 2
                count = word >> 10                    # 6-bit count, raw
                displacement = word & 0x3FF           # 10-bit, 1023 window
                if displacement == 0 or displacement > len(output):
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
