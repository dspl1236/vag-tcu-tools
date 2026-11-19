/*
 * sgo_fast.c - optional C acceleration for the SGO format-1 table ciphers.
 *
 * Ported from lsdlsd88/TCU-FRF-SGO-UNPACKER sgo_fast.c (MIT). Only the two
 * table-cipher hot loops are kept here; LZSS/LZZ decompression already has
 * pure-Python implementations in core/lzss.py and core/lzz.py.
 *
 * Both ciphers are a stateful byte-by-byte recurrence (each output byte feeds
 * the next), so they cannot be vectorised; C is a large speed-up over the
 * Python loop. The compiled library is OPTIONAL and loaded via ctypes
 * (core/sgo_fast.py); core.crypto_table.TableBlockCrypto falls back to pure
 * Python when it is absent, so a missing library only costs speed.
 *
 * Build:  python -m core.build_sgo_fast     (writes the shared library beside
 *                                            this source for the loader to find)
 *
 *   sgo_table_decrypt(table256, in, out, n)   SGO format-1 PQ/MQB cipher
 *   sgo_feedback(table256, in, out, n)        early 02EA feedback cipher
 */
#include <stddef.h>
#include <stdint.h>

#ifdef _WIN32
#define EXPORT __declspec(dllexport)
#else
#define EXPORT
#endif

/* SGO format-1 PQ/MQB cipher: table permutation plus a rolling 0x167 counter
   and the container XOR-FF layer; state starts at zero per block. */
EXPORT void sgo_table_decrypt(const uint8_t *table, const uint8_t *in,
                              uint8_t *out, size_t length)
{
    unsigned offset = 0, rolling = 0, last = 0;
    size_t i;
    for (i = 0; i < length; i++) {
        unsigned plain = table[((in[i] ^ 0xFF) + offset) & 0xFF];
        rolling = (rolling + 0x167) & 0xFFFF;
        offset = (offset + plain + last + table[(rolling >> 8) & 0xFF]) & 0xFF;
        last = plain;
        out[i] = (uint8_t)plain;
    }
}

/* Early 02EA cipher: plaintext is table[(stored + previous stored) & 0xFF],
   with 0xFF as the previous byte at the start of every block. */
EXPORT void sgo_feedback(const uint8_t *table, const uint8_t *in,
                         uint8_t *out, size_t length)
{
    unsigned previous = 0xFF;
    size_t i;
    for (i = 0; i < length; i++) {
        unsigned stored = in[i];
        out[i] = table[(stored + previous) & 0xFF];
        previous = stored;
    }
}
