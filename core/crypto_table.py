"""Table (substitution) cipher for VAG DSG/CVT SGO "format 1" blocks.

Ported from lsdlsd88/TCU-FRF-SGO-UNPACKER (MIT):
  - the rolling-offset recurrence `decrypt_table` (sgo_unpack.py), and
  - the early byte-feedback variant `decrypt_feedback` (sgo_early.py).

These decode the format-1 payloads inside SGML Object File (`.sgo`) containers
for the Temic/MQB/PQ DSG and VL381 CVT families. The 256-byte family tables
live in `platforms/sgo_tables.py`; the `.sgo` container itself is parsed by
`core.sgo`.

Both schemes fold the container's XOR-0xFF layer into the table, and the cipher
state restarts at the top of every block. This is a decrypt-only primitive: it
recovers stock plaintext from factory containers (there is no re-encode path,
the same as an unpacker needs none).
"""


class TableBlockCrypto:
    """Format-1 substitution cipher driven by a 256-byte permutation `table`.

    mode="progressive"
        The PQ/MQB rolling-0x167 recurrence — the common case, verified
        upstream on VO1b/RN1b PQ DQ250 reads.
    mode="feedback"
        The early 02EA (current + previous stored byte) cipher, verified
        upstream on the mF8J read. No rolling counter.
    """

    def __init__(self, table, mode="progressive"):
        if len(table) != 256 or len(set(table)) != 256:
            raise ValueError("cipher table must be a 256-byte permutation")
        if mode not in ("progressive", "feedback"):
            raise ValueError(f"unknown table-cipher mode {mode!r}")
        self.table = bytes(table)
        self.mode = mode

    def decrypt(self, data: bytes) -> bytes:
        # Use the optional compiled hot loop when present; the pure-Python path
        # is byte-identical and always available.
        fast = self._fast_fn()
        if fast is not None:
            return fast(self.table, data)
        if self.mode == "feedback":
            return self._feedback(data)
        return self._progressive(data)

    def _fast_fn(self):
        """Return the compiled hot-loop function, or None to use pure Python."""
        from . import sgo_fast
        if not sgo_fast.available():
            return None
        return sgo_fast.feedback if self.mode == "feedback" else sgo_fast.table_decrypt

    def _progressive(self, data: bytes) -> bytes:
        table = self.table
        offset = rolling = last = 0
        out = bytearray()
        for value in data:
            plain = table[((value ^ 0xFF) + offset) & 0xFF]
            rolling = (rolling + 0x167) & 0xFFFF
            offset = (offset + plain + last + table[rolling >> 8]) & 0xFF
            last = plain
            out.append(plain)
        return bytes(out)

    def _feedback(self, data: bytes) -> bytes:
        table = self.table
        previous = 0xFF
        out = bytearray()
        for stored in data:
            out.append(table[(stored + previous) & 0xFF])
            previous = stored
        return bytes(out)
