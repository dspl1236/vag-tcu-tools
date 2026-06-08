"""LZZ decompression — 2047-byte sliding window.

Used by ZF 8HP TCU firmware (AL551/AL552, method 0x22) after XOR decryption.
Variant of LZSS with inverted flag bits and different encoding:
  - Flag bit 0 = literal byte, 1 = back-reference
  - Reference: 5-bit count (raw) + 11-bit displacement
  - Window: 2047 bytes, max match length: 31

Verified against real ZF 8HP firmware: 1,310,208 bytes perfect match.
Format identified from chrisgotboost's NefMoto research (March 2024).
"""


def decompress_lzz(data: bytes, output_size: int = 0) -> bytearray:
    """Decompress LZZ data with 2047-byte window (ZF 8HP variant).

    Args:
        data: Compressed input bytes.
        output_size: Expected output size (0 = decompress until input exhausted).

    Returns:
        Decompressed bytearray.
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
            # Inverted flags: 0 = literal, 1 = reference
            if not (flag & (1 << (7 - bit))):
                output.append(data[i])
                i += 1
            else:
                if i + 1 >= len(data):
                    break
                b0 = data[i]
                b1 = data[i + 1]
                i += 2
                count = b0 >> 3                          # 5-bit count (raw)
                displacement = ((b0 & 0x07) << 8) | b1   # 11-bit displacement
                if displacement == 0:
                    displacement = 1
                start = len(output) - displacement
                for j in range(count):
                    if start + j < 0:
                        output.append(0)
                    else:
                        output.append(output[start + j])
    if output_size:
        return output[:output_size]
    return output
