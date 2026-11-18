"""SGML Object File (SGO v2) parser/unpacker.

Ported from lsdlsd88/TCU-FRF-SGO-UNPACKER `sgo_unpack.py` (MIT), which is
itself a port of calledit's `SGML_Object_File_reader` (read_sgo.php), extended
for the getriebe (DSG/CVT TCU) files. The pure-Python table-cipher accelerator
(`sgo_fast`) and the split feedback module are dropped here; format-1 decoding
goes through a `core.crypto_table.TableBlockCrypto` the caller supplies.

Layout (all u32 = little-endian):
  0x00  "SGML Object File\\0"       (17 bytes)
  0x11  u32 compat (=2)
  0x15  u32 checksum
  0x19  u32 indexIDENT
  0x1d  u32 indexBaudrate2000
  0x21  u32 indexKwp2000Rei
  0x25  u32 indexKwp2000Acp
  0x29  u32 indexKwp2000Sa2
  0x2d  u32 indexDataBlocks      (points at [count][offsets...])
  IDENT: 260-byte XOR-FF filename field; 5-byte version field; u32
  SA2:   u32 count; count bytes script
  DataBlocks table: u32 count; count x u32 descriptor offsets
  Descriptor (0x19 bytes) at each offset:
    +0x00 3B id/start, +0x03 1B format, +0x04 3B size_after_decomp,
    +0x07 3B erase_start, +0x0a 3B erase_end, +0x0d 3B check_start,
    +0x10 3B check_end, +0x13 2B checksum, +0x15 u32 data_size
    then data_size bytes of payload. Format 0 is XOR-FF plaintext;
    format 1 needs a family cipher even when stored/decoded sizes match.
Three-byte addresses/sizes are big-endian (as in the PHP reader).
"""

import struct
from pathlib import Path

HEADER_MAGIC = b"SGML Object File\x00"


def be24(b: bytes) -> int:
    return (b[0] << 16) | (b[1] << 8) | b[2]


def le24(b: bytes) -> int:
    return b[0] | (b[1] << 8) | (b[2] << 16)


_XOR_FF_TABLE = bytes(i ^ 0xFF for i in range(256))


def xorff(b: bytes) -> bytes:
    """Container XOR-0xFF layer (C-speed via bytes.translate)."""
    return bytes(b).translate(_XOR_FF_TABLE)


def xorff_str(b: bytes) -> str:
    out = []
    for c in b:
        if c == 0:
            break
        out.append(c ^ 0xFF)
    return bytes(out).decode("latin1")


class SGO:
    """A parsed SGML Object File. Pass a path, or raw `data` to parse in memory."""

    def __init__(self, path, data=None):
        self.path = Path(path) if path is not None else None
        self.data = self.path.read_bytes() if data is None else bytes(data)
        d = self.data
        if not d.startswith(HEADER_MAGIC):
            raise ValueError("not an SGML Object File")
        self.require(0, 0x31, "header")
        (
            self.compat,
            self.checksum,
            self.i_ident,
            self.i_baud,
            self.i_rei,
            self.i_acp,
            self.i_sa2,
            self.i_blocks,
        ) = struct.unpack_from("<8I", d, 0x11)
        if self.compat != 2:
            raise ValueError(f"unsupported SGO compatibility {self.compat}")

    def require(self, offset, size, label):
        if offset < 0 or size < 0 or offset + size > len(self.data):
            raise ValueError(
                f"truncated {label}: need {size:#x} bytes at {offset:#x}, "
                f"file size is {len(self.data):#x}"
            )

    def parse(self):
        d = self.data
        self.require(self.i_ident, 269, "IDENT")
        self.name = xorff_str(d[self.i_ident:self.i_ident + 260])
        vpos = self.i_ident + 260
        self.version = xorff_str(d[vpos:vpos + 5])

        self.require(self.i_sa2, 4, "SA2 count")
        self.sa2_count = struct.unpack_from("<I", d, self.i_sa2)[0]
        self.require(self.i_sa2 + 4, self.sa2_count, "SA2 script")
        self.sa2 = d[self.i_sa2 + 4:self.i_sa2 + 4 + self.sa2_count]

        self.blocks = []
        self.require(self.i_blocks, 4, "block index count")
        nb = struct.unpack_from("<I", d, self.i_blocks)[0]
        self.require(self.i_blocks + 4, nb * 4, "block index")
        self.block_offsets = struct.unpack_from(f"<{nb}I", d, self.i_blocks + 4)
        for bo in self.block_offsets:
            self.require(bo, 0x19, "block descriptor")
            raw = d[bo:bo + 0x19]
            blk = {
                "raw": raw,
                "id_le": le24(raw[0:3]),
                "id_be": be24(raw[0:3]),
                "format": raw[3],
                "decomp_be": be24(raw[4:7]),
                "erase": (be24(raw[7:10]), be24(raw[10:13])),
                "check": (be24(raw[13:16]), be24(raw[16:19])),
                "cksum": raw[19:21].hex(),
                "dsize": struct.unpack_from("<I", raw, 0x15)[0],
            }
            self.require(bo + 0x19, blk["dsize"], "block payload")
            blk["data"] = d[bo + 0x19:bo + 0x19 + blk["dsize"]]
            self.blocks.append(blk)
        return self

    def decode_block(self, index, crypto=None):
        """Return the plaintext for block `index`.

        Format 0 is container XOR-0xFF plaintext (no `crypto` needed). Format 1
        needs a `core.crypto_table.TableBlockCrypto` for the block's family.
        Raises ValueError if the decoded size disagrees with the descriptor
        (these blocks are not additionally compressed).
        """
        block = self.blocks[index]
        fmt = block["format"]
        if fmt == 0:
            result = xorff(block["data"])
        elif fmt == 1:
            if crypto is None:
                raise ValueError("format 0x01 requires a family cipher (TableBlockCrypto)")
            result = crypto.decrypt(block["data"])
        else:
            raise ValueError(f"unsupported block format {fmt:#04x}")
        if len(result) != block["decomp_be"]:
            raise ValueError(
                f"decoded size {len(result):#x} differs from descriptor "
                f"{block['decomp_be']:#x} (wrong cipher table, or unsupported compression)"
            )
        return result

    def summary(self) -> str:
        lines = [
            f"file: {self.path.name if self.path else '<memory>'} ({len(self.data)} bytes)",
            f"compat={self.compat} checksum={self.checksum:#010x}",
            f"name={self.name!r} version={self.version!r}",
            f"sa2({self.sa2_count})={self.sa2.hex()}",
            f"blocks: {len(self.blocks)}",
        ]
        for i, b in enumerate(self.blocks):
            lines.append(
                f"  [{i}] @{self.block_offsets[i]:#x}: id(le/be)={b['id_le']}/{b['id_be']:#x} "
                f"fmt={b['format']} decomp={b['decomp_be']:#x} "
                f"erase={b['erase'][0]:#06x}-{b['erase'][1]:#06x} "
                f"check={b['check'][0]:#06x}-{b['check'][1]:#06x} "
                f"cksum={b['cksum']} dsize={b['dsize']:#x} (actual {len(b['data'])})"
            )
        return "\n".join(lines)


def parse_sgo(path=None, data=None) -> SGO:
    """Parse an SGO from a path or from raw bytes."""
    return SGO(path, data=data).parse()
