"""LZZ compressor round-trips through the decompressor (ZF 8HP method 0x22)."""
import random
from core.lzz import compress_lzz, decompress_lzz


def _rt(data):
    return bytes(decompress_lzz(compress_lzz(data), len(data))) == data


def test_roundtrip_edge_and_patterns():
    assert _rt(b"")
    assert _rt(b"A")
    assert _rt(b"ABCD" * 5000)                 # highly repetitive
    assert _rt(b"\x00" * 8000 + b"\xff" * 4000)  # RLE runs
    assert _rt(b"\x01\x02" * 100)              # short-period / overlapping


def test_roundtrip_random():
    random.seed(42)
    for n in (1, 7, 100, 20000):
        assert _rt(bytes(random.randrange(256) for _ in range(n)))


def test_reference_format_limits():
    # a run longer than max match length (31) must still round-trip (multiple refs)
    assert _rt(b"Z" * 2000)
    # a match at the window limit (2047) round-trips
    assert _rt(b"q" + b"\x00" * 2046 + b"q" * 4)
