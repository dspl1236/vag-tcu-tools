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


# --- Compressor (encoder) ---------------------------------------------------
# Greedy longest-match with 3-byte hash chains. The exact inverse of
# decompress_lzz above. Output is not byte-identical to VW's encoder (many valid
# LZ encodings exist) but decompresses back to the exact input, which is all the
# ECU bootloader requires. Verified round-trip on real 4G0927158 firmware.
_WINMAX = 2047
_MAXLEN = 31
_MINLEN = 3
_MAXCHAIN = 256


def compress_lzz(data: bytes) -> bytes:
    """Compress to the ZF 8HP LZZ format (inverse of decompress_lzz)."""
    n = len(data)
    out = bytearray()
    head: dict[int, int] = {}
    prev = [-1] * n

    def h3(p):
        return (data[p] << 16) | (data[p + 1] << 8) | data[p + 2]

    def insert(p):
        if p + 2 < n:
            k = h3(p); prev[p] = head.get(k, -1); head[k] = p

    i = 0
    while i < n:
        flag_i = len(out); out.append(0); flag = 0
        for bit in range(8):
            if i >= n:
                break
            best_len = 0; best_disp = 0
            if i + 2 < n:
                cand = head.get(h3(i), -1); chain = 0
                while cand >= 0 and (i - cand) <= _WINMAX and chain < _MAXCHAIN:
                    d = i - cand; l = 0
                    while l < _MAXLEN and i + l < n and data[i + l] == data[i - d + l]:
                        l += 1
                    if l > best_len:
                        best_len = l; best_disp = d
                        if l >= _MAXLEN:
                            break
                    cand = prev[cand]; chain += 1
            if best_len >= _MINLEN:
                flag |= (1 << (7 - bit))
                out.append((best_len << 3) | ((best_disp >> 8) & 7))
                out.append(best_disp & 0xFF)
                for k in range(best_len):
                    insert(i + k)
                i += best_len
            else:
                out.append(data[i]); insert(i); i += 1
        out[flag_i] = flag
    return bytes(out)
