"""Repeating XOR block encryption for ZF 8HP platforms.

Used by ZF 8HP TCU firmware (AL551, method 0x22).
The key is a fixed ASCII string XOR'd cyclically against the data.
See docs/KEYS.md for known keys.
"""


class XORBlockCrypto:
    """Repeating-key XOR encrypt/decrypt (symmetric)."""

    def __init__(self, key: bytes):
        if not key:
            raise ValueError("XOR key must not be empty")
        self.key = key
        self.key_len = len(key)

    def decrypt(self, data: bytes) -> bytes:
        """Decrypt data by XOR with repeating key.  Symmetric."""
        out = bytearray(len(data))
        for i in range(len(data)):
            out[i] = data[i] ^ self.key[i % self.key_len]
        return bytes(out)

    def encrypt(self, data: bytes) -> bytes:
        """Encrypt data by XOR with repeating key.  Symmetric with decrypt."""
        return self.decrypt(data)
