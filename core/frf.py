"""FRF container decryption.

All VAG flashdaten .frf files are ZIP archives encrypted with a rolling
XOR cipher.  The key material is a 4095-byte file (frf.key) common to
all VW Group platforms.

Algorithm from bri3d/VW_Flash (MIT).
"""

from pathlib import Path


def decrypt_frf(key_material: bytes, encrypted_data: bytes) -> bytes:
    """Decrypt an FRF container using the rolling XOR cipher.

    Returns a ZIP archive (starts with b'PK').
    """
    output = bytearray()
    key_index = 0
    first_seed = 0
    second_seed = 1
    for data_byte in encrypted_data:
        key_byte = key_material[key_index]
        first_seed = ((first_seed + key_byte) * 3) & 0xFF
        decrypted_byte = data_byte ^ (first_seed ^ 0xFF ^ second_seed ^ key_byte)
        output.append(decrypted_byte)
        second_seed = ((second_seed + 1) * first_seed) & 0xFF
        key_index = (key_index + 1) % len(key_material)
    return bytes(output)


def encrypt_frf(key_material: bytes, plain_data: bytes) -> bytes:
    """Encrypt data back into FRF format.  Symmetric with decrypt."""
    return decrypt_frf(key_material, plain_data)


def load_frf_key(key_path: str | None = None) -> bytes:
    """Load frf.key from *key_path* or the default data/ location."""
    if key_path:
        return Path(key_path).read_bytes()
    default = Path(__file__).parent.parent / "data" / "frf.key"
    if default.exists():
        return default.read_bytes()
    raise FileNotFoundError(
        "frf.key not found.  Copy from VW_Flash data/frf.key to data/frf.key "
        "or pass key_path explicitly."
    )
