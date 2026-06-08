"""LZSS decompression — 1023-byte sliding window.

Used by DQ381 (BL301, method 0x0A) after AES decryption.
Big-endian: 6-bit count + 10-bit displacement.
Based on bri3d/VW_Flash (MIT).
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
                start = len(output) - displacement
                for j in range(count):
                    output.append(output[start + j])
    if output_size:
        return output[:output_size]
    return output
