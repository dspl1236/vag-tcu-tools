"""ODX and ODX-F flash block extractor.

Parses VAG flashdaten ODX XML to extract flash block binaries.
Handles both inline hex (ODX, BL301 era) and external .bin files
(ODX-F, BL401 era).  Applies the correct decrypt + decompress
pipeline based on the ENCRYPT-COMPRESS-METHOD field.

Method encoding: two hex characters XY
  X = compression type (0=none, 2=LZZ, A=LZSS)
  Y = encryption type  (0=none, 1=AES, 2=XOR, A=AES)
"""

import binascii
import io
import os
import xml.etree.ElementTree as ET
from pathlib import Path
from zipfile import ZipFile

from .frf import decrypt_frf, load_frf_key
from .lzss import decompress_lzss
from .lzz import decompress_lzz


def _decrypt_block(raw: bytes, method: str, crypto) -> bytes:
    """Decrypt a flash block based on the method's encryption type."""
    enc_type = method[1].upper() if len(method) >= 2 else "0"
    if enc_type == "0":
        return raw
    if crypto is None:
        return raw  # No crypto configured — return as-is
    return crypto.decrypt(raw)


def _decompress_block(data: bytes, method: str, output_size: int) -> bytearray:
    """Decompress a flash block based on the method's compression type."""
    comp_type = method[0].upper() if len(method) >= 2 else "0"
    if comp_type == "A":
        return decompress_lzss(data, output_size)
    if comp_type == "2":
        return decompress_lzz(data, output_size)
    return bytearray(data)


def extract_frf_blocks(
    frf_path: str,
    crypto=None,
    key_path: str | None = None,
    output_dir: str | None = None,
) -> dict[str, bytearray]:
    """Full pipeline: FRF → ODX/ODX-F → decrypted/decompressed blocks.

    Args:
        frf_path: Path to the .frf file.
        crypto: AESBlockCrypto or XORBlockCrypto instance (or None).
        key_path: Path to frf.key (default: data/frf.key).
        output_dir: Write extracted blocks to this directory.

    Returns:
        Dict mapping block identifier → raw binary data.
    """
    frf_key = load_frf_key(key_path)
    frf_data = Path(frf_path).read_bytes()
    decrypted = decrypt_frf(frf_key, frf_data)

    if decrypted[:2] != b"PK":
        raise ValueError("FRF decryption failed (not a ZIP)")

    zf = ZipFile(io.BytesIO(decrypted), "r")
    contents = {name: zf.read(name) for name in zf.namelist()}
    zf.close()

    # Detect format
    odx_file = odxf_file = None
    bin_files = {}
    for name, data in contents.items():
        lower = name.lower()
        if lower.endswith(".odx") and not lower.endswith(".odx-f"):
            odx_file = data
        elif lower.endswith(".odx-f"):
            odxf_file = data
        elif lower.endswith(".bin"):
            bin_files[name] = data

    if odx_file:
        blocks = _parse_odx_inline(odx_file.decode("utf-8", errors="replace"), crypto)
    elif odxf_file:
        blocks = _parse_odxf(odxf_file.decode("utf-8", errors="replace"), bin_files, crypto)
    else:
        raise ValueError(f"No ODX/ODX-F in FRF: {list(contents.keys())}")

    if output_dir:
        os.makedirs(output_dir, exist_ok=True)
        for block_id, block_data in blocks.items():
            out_path = os.path.join(output_dir, block_id)
            Path(out_path).write_bytes(block_data)

    return blocks


def _parse_odx_inline(odx_str: str, crypto) -> dict[str, bytearray]:
    """Parse ODX with inline hex data (BL301 era)."""
    root = ET.fromstring(odx_str)
    blocks = {}

    for flashdata in root.findall(".//FLASHDATA"):
        data_els = flashdata.findall("./DATA")
        if not data_els or not data_els[0].text:
            continue
        content = data_els[0].text.strip()
        if len(content) <= 4:
            continue

        method = flashdata.findtext("ENCRYPT-COMPRESS-METHOD", "00").strip()
        fd_id = flashdata.get("ID", "unknown")

        size_els = root.findall(
            f".//DATABLOCK/FLASHDATA-REF[@ID-REF='{fd_id}']"
            f"/../SEGMENTS/SEGMENT/UNCOMPRESSED-SIZE"
        )
        decomp_size = int(size_els[0].text) if size_els else 0

        raw = binascii.unhexlify(content)
        try:
            decrypted = _decrypt_block(raw, method, crypto)
            result = _decompress_block(decrypted, method, decomp_size) if decomp_size else bytearray(decrypted)
            blocks[fd_id] = result
        except Exception:
            blocks[fd_id + ".encrypted"] = bytearray(raw)

    return blocks


def _parse_odxf(odxf_str: str, bin_files: dict, crypto) -> dict[str, bytearray]:
    """Parse ODX-F with external .bin files (BL401 era)."""
    root = ET.fromstring(odxf_str)
    blocks = {}

    for flashdata in root.findall(".//FLASHDATA"):
        fd_id = flashdata.get("ID", "")
        datafile = flashdata.findtext("DATAFILE", "").strip()
        method = flashdata.findtext("ENCRYPT-COMPRESS-METHOD", "00").strip()

        if not datafile or datafile not in bin_files:
            continue

        size_els = root.findall(
            f".//DATABLOCK/FLASHDATA-REF[@ID-REF='{fd_id}']"
            f"/../SEGMENTS/SEGMENT/UNCOMPRESSED-SIZE"
        )
        decomp_size = int(size_els[0].text) if size_els else len(bin_files[datafile])

        raw = bin_files[datafile]
        try:
            decrypted = _decrypt_block(raw, method, crypto)
            result = _decompress_block(decrypted, method, decomp_size)
            blocks[fd_id] = result
        except Exception:
            blocks[fd_id + ".encrypted"] = bytearray(raw)

    return blocks
