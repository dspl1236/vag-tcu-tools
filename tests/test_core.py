"""Tests for vag-flash-tools."""

import hashlib
import struct

import pytest

from core import __version__
from core.checksum import crc32_fix, crc32_validate
from core.crypto_aes import AESBlockCrypto
from core.crypto_table import TableBlockCrypto
from core.crypto_xor import XORBlockCrypto
from core.frf import decrypt_frf, encrypt_frf
from core.lzss import decompress_lzss
from core.lzz import decompress_lzz
from core.sgo import SGO, parse_sgo, xorff
from platforms.sgo_tables import FAMILIES, TABLES, crypto_for, get_table


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
        from platforms.dq381 import BL301_IV, BL301_KEY
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
        """Inverted flags: flag 0x00 = all 8 tokens are literals."""
        compressed = bytes([0x00]) + b"ABCDEFGH"
        result = decompress_lzss(compressed)
        assert result == bytearray(b"ABCDEFGH")

    def test_back_reference(self):
        """Flag bit set = back-reference; word 0x0C08 => copy 3 bytes from -8."""
        compressed = bytes([0x00]) + b"ABCDEFGH" + bytes([0x80, 0x0C, 0x08])
        result = decompress_lzss(compressed, 11)
        assert result == bytearray(b"ABCDEFGHABC")

    def test_out_of_range_displacement_raises(self):
        """A back-reference past the output start fails cleanly, not corrupt.

        Flag 0x80 makes the first token a reference, but nothing has been
        decoded yet, so the displacement is out of range.
        """
        with pytest.raises(ValueError, match="displacement"):
            decompress_lzss(bytes([0x80, 0x00, 0x05]))


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
        valid, _stored, _computed = crc32_validate(
            bytes(fixed), block_base=base)
        assert valid

    def test_crc32_validate_crc_cell_before_range(self):
        """CAL-style: the CRC cell (0x44) sits before the CRC'd range (0x100..),
        so it is excluded from the checksum, not zeroed via a negative index."""
        block = bytearray(0x400)
        base = 0x140200
        struct.pack_into(">I", block, 0x38, base + 0x100)   # range_start = 0x100
        struct.pack_into(">I", block, 0x3C, base + 0x3FF)   # range_end = 0x3FF
        for i in range(0x100, 0x400):
            block[i] = (i * 7) & 0xFF
        fixed = crc32_fix(block, block_base=base)
        valid, _stored, _computed = crc32_validate(bytes(fixed), block_base=base)
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


class TestKeyImport:
    def test_extract_boot_key(self):
        """Pull the AES key/IV from their plaintext BOOT offsets (0x344/0x354)."""
        from platforms.dq381 import BOOT_KEY_BASE, extract_boot_key
        dump = bytearray(0x400)
        iv = bytes(range(0x10, 0x20))
        key = bytes(range(0x10))
        dump[0x344:0x354] = iv
        dump[0x354:0x364] = key
        got_key, got_iv = extract_boot_key(bytes(dump), base=BOOT_KEY_BASE)
        assert got_key == key
        assert got_iv == iv

    def test_extract_boot_key_out_of_range(self):
        """A too-small dump fails cleanly rather than slicing garbage."""
        from platforms.dq381 import extract_boot_key
        with pytest.raises(ValueError, match="offset"):
            extract_boot_key(b"\x00" * 16)


class TestSgoTables:
    def test_all_tables_are_permutations(self):
        """Every recovered table must be a 256-byte permutation."""
        assert len(TABLES) == 10
        for name, table in TABLES.items():
            assert len(table) == 256, name
            assert len(set(table)) == 256, name

    def test_known_table_hashes(self):
        """Pin two tables by SHA-256 so a bad edit is caught."""
        assert hashlib.sha256(get_table("dq250_pq")).hexdigest()[:16] == "72d854441ebd4e3b"
        assert hashlib.sha256(get_table("dq250_early")).hexdigest()[:16] == "5d09da393a8051c1"

    def test_families_reference_valid_tables(self):
        for family, (table_name, mode, _desc) in FAMILIES.items():
            assert table_name in TABLES, family
            assert mode in ("progressive", "feedback"), family

    def test_get_table_unknown_raises(self):
        with pytest.raises(ValueError, match="unknown cipher table"):
            get_table("nope")


class TestTableCipher:
    def test_progressive_known_answer(self):
        """Pin the rolling-0x167 cipher (the pure-Python fallback CI runs)."""
        crypto = TableBlockCrypto(get_table("dq250_pq"), "progressive")
        assert crypto._progressive(bytes(range(8))).hex() == "2362615114f5085a"

    def test_feedback_known_answer(self):
        """Pin the early 02EA byte-feedback cipher."""
        crypto = TableBlockCrypto(get_table("dq250_early"), "feedback")
        assert crypto._feedback(bytes(range(8))).hex() == "7a68df5964013cea"

    def test_decrypt_matches_pure_python(self):
        """The public path (C when built) must equal the pure-Python loop."""
        data = bytes((i * 37 + 11) & 0xFF for i in range(500))
        prog = TableBlockCrypto(get_table("mqb_dsg"), "progressive")
        assert prog.decrypt(data) == prog._progressive(data)
        fb = TableBlockCrypto(get_table("dq250_early"), "feedback")
        assert fb.decrypt(data) == fb._feedback(data)

    def test_length_preserving(self):
        crypto = crypto_for("dq400e")
        assert len(crypto.decrypt(bytes(321))) == 321

    def test_crypto_for_mode(self):
        assert crypto_for("dq250_early").mode == "feedback"
        assert crypto_for("dq250pq").mode == "progressive"

    def test_crypto_for_unknown_raises(self):
        with pytest.raises(ValueError, match="unknown family"):
            crypto_for("nope")

    def test_bad_table_raises(self):
        with pytest.raises(ValueError, match="256-byte permutation"):
            TableBlockCrypto(b"\x00" * 255)

    def test_bad_mode_raises(self):
        with pytest.raises(ValueError, match="unknown table-cipher mode"):
            TableBlockCrypto(bytes(range(256)), "nope")


def _build_sgo(blocks):
    """Assemble a minimal valid SGO v2 container for the parser tests.

    `blocks` is a list of (format, decomp_size, payload). Text fields terminate
    with a plaintext 0xFF (stored 0x00), which is where xorff_str stops.
    """
    buf = bytearray(b"SGML Object File\x00")
    hdr = len(buf)
    buf += b"\x00" * 32
    ident = len(buf)
    buf += xorff(b"TESTSGO" + b"\xff" * (260 - 7))
    buf += xorff(b"E01" + b"\xff" * (5 - 3))
    buf += struct.pack("<I", 0)
    sa2 = len(buf)
    script = bytes.fromhex("68028149")
    buf += struct.pack("<I", len(script)) + script
    offs = []
    for fmt, decomp, payload in blocks:
        offs.append(len(buf))
        desc = bytearray(0x19)
        desc[0:3] = b"\x00\x00\x01"
        desc[3] = fmt
        desc[4:7] = bytes(((decomp >> 16) & 0xFF, (decomp >> 8) & 0xFF, decomp & 0xFF))
        struct.pack_into("<I", desc, 0x15, len(payload))
        buf += desc + payload
    blkidx = len(buf)
    buf += struct.pack("<I", len(offs))
    buf += b"".join(struct.pack("<I", o) for o in offs)
    struct.pack_into("<8I", buf, hdr, 2, 0, ident, 0, 0, 0, sa2, blkidx)
    return bytes(buf)


class TestSgo:
    def test_parse_and_decode_format0(self):
        plain = bytes(range(200))
        obj = parse_sgo(data=_build_sgo([(0, len(plain), xorff(plain))]))
        assert obj.name == "TESTSGO"
        assert obj.version == "E01"
        assert obj.sa2.hex() == "68028149"
        assert obj.decode_block(0) == plain

    def test_format1_decode_and_requires_crypto(self):
        crypto = crypto_for("dq250pq")
        payload = bytes((i * 29 + 3) & 0xFF for i in range(123))
        decoded = crypto.decrypt(payload)           # length-preserving
        obj = parse_sgo(data=_build_sgo([(1, len(decoded), payload)]))
        with pytest.raises(ValueError, match="family cipher"):
            obj.decode_block(0)
        assert obj.decode_block(0, crypto=crypto) == decoded

    def test_not_an_sgo_raises(self):
        with pytest.raises(ValueError, match="not an SGML Object File"):
            SGO(None, data=b"not an sgo file")

    def test_truncated_block_index_raises(self):
        good = bytearray(_build_sgo([(0, 8, xorff(bytes(8)))]))
        # Point the block index past EOF.
        struct.pack_into("<I", good, 0x2d, len(good) + 0x100)
        with pytest.raises(ValueError, match="truncated"):
            parse_sgo(data=bytes(good))
