"""Tests for vag-flash-tools."""

import struct
from core import __version__
from core.crypto_aes import AESBlockCrypto
from core.crypto_xor import XORBlockCrypto
from core.lzss import decompress_lzss
from core.lzz import decompress_lzz
from core.checksum import crc32_validate, crc32_fix
from core.frf import decrypt_frf, encrypt_frf


class TestVersion:
    def test_version(self):
        assert __version__ == "0.3.0"


class TestAESCrypto:
    def test_roundtrip(self):
        key = bytes(range(16))
        iv = bytes(range(0x10, 0x20))
        c = AESBlockCrypto(key, iv)
        data = b"hello world!!!!!" * 4  # 64 bytes
        enc = c.encrypt(data)
        dec = c.decrypt(enc)
        assert dec[:len(data)] == data

    def test_dq381_key(self):
        from platforms.dq381 import BL301_KEY, BL301_IV
        assert BL301_KEY == bytes(range(16))
        assert BL301_IV == bytes(range(0x10, 0x20))


class TestXORCrypto:
    def test_roundtrip(self):
        key = b"CyA2008ZFVAGtcuxsam"
        c = XORBlockCrypto(key)
        data = b"test data for xor encryption roundtrip"
        enc = c.encrypt(data)
        dec = c.decrypt(enc)
        assert dec == data

    def test_zf8hp_key(self):
        from platforms.zf8hp import XOR_KEY
        assert XOR_KEY == b"CyA2008ZFVAGtcuxsam"
        assert len(XOR_KEY) == 19

    def test_symmetric(self):
        c = XORBlockCrypto(b"testkey")
        data = bytes(range(256))
        assert c.decrypt(c.encrypt(data)) == data


class TestLZSS:
    def test_all_literal(self):
        """Flag 0xFF = all 8 bits are literals."""
        compressed = bytes([0xFF]) + b"ABCDEFGH"
        result = decompress_lzss(compressed)
        assert result == bytearray(b"ABCDEFGH")


class TestLZZ:
    def test_all_literal(self):
        """Flag 0x00 = all 8 bits are literals (inverted flags)."""
        compressed = bytes([0x00]) + b"ABCDEFGH"
        result = decompress_lzz(compressed)
        assert result == bytearray(b"ABCDEFGH")

    def test_known_decompression(self):
        """Verify the first few bytes of ZF 8HP decompression."""
        # First 9 compressed bytes: flag=0x00 + 8 literal bytes
        compressed = bytes.fromhex("00876543c100000000")
        result = decompress_lzz(compressed, 8)
        assert result == bytearray.fromhex("876543c100000000")


class TestFRF:
    def test_roundtrip(self):
        key = bytes(range(1, 100))
        data = b"test frf data" * 10
        enc = encrypt_frf(key, data)
        dec = decrypt_frf(key, enc)
        assert dec == data


class TestChecksum:
    def test_crc32_fix_roundtrip(self):
        """Create a block, fix checksum, then validate."""
        data = bytearray(261632)
        base = 0x140200
        # Set range pointers
        struct.pack_into(">I", data, 0x38, base)
        struct.pack_into(">I", data, 0x3C, base + len(data) - 1)
        fixed = crc32_fix(data, block_base=base)
        valid, stored, computed = crc32_validate(
            bytes(fixed), block_base=base)
        assert valid


class TestPlatformConfigs:
    def test_dq381_addresses(self):
        from platforms.dq381 import CAL_ADDRESSES
        assert CAL_ADDRESSES["torque_cap_drive"] == 0x28138
        assert CAL_ADDRESSES["rev_limiter_primary"] == 0x0333A

    def test_zf8hp_families(self):
        from platforms.zf8hp import FAMILIES, XOR_KEY
        assert "4G0927158" in FAMILIES
        assert "4H1927158" in FAMILIES
        assert XOR_KEY == b"CyA2008ZFVAGtcuxsam"

    def test_zf8hp_memory_map(self):
        from platforms.zf8hp import MEMORY_MAP
        assert MEMORY_MAP["ASW"]["start"] == 0x040080
        assert MEMORY_MAP["CAL_DATA"]["start"] == 0x190000
