"""AES-128-CBC block encryption for VAG flash blocks.

Used by DQ381 (BL301), DQ500, and Simos ECU families.
Each platform has its own key/IV pair — see docs/KEYS.md.
"""

from Crypto.Cipher import AES


class AESBlockCrypto:
    """AES-128-CBC encrypt/decrypt with configurable key and IV."""

    def __init__(self, key: bytes, iv: bytes):
        if len(key) != 16:
            raise ValueError(f"AES-128 requires 16-byte key, got {len(key)}")
        if len(iv) != 16:
            raise ValueError(f"AES-CBC requires 16-byte IV, got {len(iv)}")
        self.key = key
        self.iv = iv

    def decrypt(self, data: bytes) -> bytes:
        """Decrypt data using AES-128-CBC."""
        cipher = AES.new(self.key, AES.MODE_CBC, iv=self.iv)
        return cipher.decrypt(data)

    def encrypt(self, data: bytes) -> bytes:
        """Encrypt data using AES-128-CBC (zero-padded to 16-byte boundary)."""
        pad_len = (16 - len(data) % 16) % 16
        padded = data + b"\x00" * pad_len
        cipher = AES.new(self.key, AES.MODE_CBC, iv=self.iv)
        return cipher.encrypt(padded)
