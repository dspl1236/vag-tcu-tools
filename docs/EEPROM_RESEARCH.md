# SH72549 Emulated-EEPROM Segment Checksums — status & findings

**Status: SOLVED for DQ381 (dump-validated 2026-11-16).** Implemented in
`core/checksum.py` (`eel_eeprom_validate` / `eel_eeprom_fix`). The ZF 8HP case uses a
different NV layout (AUTOSAR NvM/Fee — see RE notes below), not the 8×16 KB construct.

The EEPROM content does **not** appear in VAG flashdaten (FRF) — it's per-unit NV
data — so it was out of scope for the flashdaten pass, not missed.

## SOLVED — DQ381 EEL data checksum

The 128 KB data flash is a Renesas **EEL** (EEPROM Emulation Library) ring: 8 × 16 KB
copies of one logical block; the live copy with the highest u32 write-counter (@0x08)
wins. Per 16 KB copy:

| Offset | Field |
|---|---|
| 0x00 | u32 EEL status (`0x4001007c` live) |
| 0x04 | u32 data size, BE (`0x21b4` on units seen) |
| 0x08 | u32 write counter, BE |
| 0x0c | SW tag (`"d13716"`) |
| **0x50** | **u32 DATA CHECKSUM, big-endian** |
| 0x54 | u16 EEL management/wear state (payload-independent, **not** a data checksum) |
| 0x56 | u16 `0xffff` |
| 0x80 | user data, `size` bytes |

**Checksum = 32-bit big-endian word-sum of the data region** `[0x80 : 0x80+size]`,
stored big-endian at **0x50**. Reproduced byte-exact on all 7 live blocks of a real
DQ381 dump (segs 0-4, 6, 7; seg5 spare).

**This resolves the community "two checksums per segment."** There is one 32-bit
checksum stored as two halves: the forum's "solved" value is its **low 16 bits**
(0x52-0x53), the "second checksum" that defeated them is its **upper 16 bits**
(0x50-0x51). A tool that rewrote only 0x52-0x53 still fails the ECU — it must recompute
and write all four bytes **0x50-0x53**.

**The 0x54 word is not crackable as a data checksum and does not need to be:** every
CRC-8 / CRC-16 / sum / hash was ruled out 7/7 (two blocks with identical data-sums differ
here), it tracks the ring write-counter, and it is independent of the payload — EEL
bookkeeping the library assigns on write, left untouched when editing data in place.

## Two ways to crack it

### A. Empirical, from a dump — `tools/eeprom_checksum_hunt.py` (built, validated)
Given a real 128 KB dump, the hunter brute-tests a battery of checksum algorithms ×
candidate stored-field positions × candidate covered-ranges, and reports any that
reproduce the stored value **across all 8 segments**. That multi-segment consistency
is the discriminator — a real algorithm matches every segment; coincidences don't.

- **Battery:** CRC-16 (CCITT-false/xmodem/aug/kermit/genibus/modbus/arc/maxim/usb),
  CRC-32 (zlib/bzip2/posix/mpeg2), sum/negsum/xor (8/16/32, LE+BE), Fletcher-16/32,
  Adler-32. Field sizes 2 B and 4 B, both endians.
- **Range model:** `before` / `after` / `whole` (ex-field) plus block-based
  `after_hdr` / `before_ftr` / `core` — the last three model checksums stored in a
  header/footer block covering the payload between (the common non-circular layout).
- **Battery now includes CRC-8/0x2F** (the AUTOSAR "H2F" poly, confirmed present in the
  ZF ASW — see RE findings below) plus 1-byte fields. **Validated:** `--selftest` builds a
  synthetic 8×16 KB EEPROM with three known checksums (crc32 + sum32 + crc8/0x2F) and
  recovers all three, 8/8 segments. Proven before any real dump exists.
- **Run:** `py -3 tools/eeprom_checksum_hunt.py dump_128k.bin` (add `--wide` to scan
  every offset, `--min-match 7` to tolerate one bad segment).

If the hunt comes back empty, the scheme is non-trivial (seeded, sub-range, or
chained CRC) — fall through to route B.

### B. Static RE of the ASW routine — definitive, needs firmware
The EEPROM write/verify code lives in the SH72549 **ASW**. Decrypt a ZF 8HP
method-0x22 FRF (`core/frf.py` + `crypto_xor` + `lzz`, key in README) or a DQ381 FRF
(AES, key in `docs/KEYS.md`) → load the ASW into Ghidra with the **SH-2A / SuperH**
processor (big-endian) → find the data-flash (FCU) write path and read the checksum
math directly. Reference hardware: `D:\DQ\REN_r01uh0480ej0400_sh7254r` (hardware
manual) + `REN_rej09b0051_sh2a` (programming manual).

## RE findings — ZF 8HP ASW decompiled (2026-11-16)

Decrypted the `4G0927158AH` ZF 8HP ASW from the flashdaten (`Q:\ECU FLASH`) via the repo's own
FRF→ODX→XOR→LZZ pipeline (1,309,696 B, SH-2A BE @ 0x040080) and reverse-engineered it in Ghidra.
The checksum **primitives are pinned byte-exact**; the exact per-segment wiring is not.

**CONFIRMED (CRC tables recomputed byte-exact in the image):** the firmware is AUTOSAR and embeds
the AUTOSAR CRC library:

| Primitive | Poly | refin | Table @ flash |
|---|---|---|---|
| CRC-16/CCITT (`Crc_CalculateCRC16`) | 0x1021 | False | 0x43000 |
| CRC-8/0x2F (`Crc_CalculateCRC8H2F`, SAE-J1850) | 0x2F | False | 0x46aa8 |
| CRC-32 (zlib) | 0x04C11DB7 | True | 0x43200 / 0x43fe4 |

**NOT pinned (honest):** which CRC covers which byte range, stored at which per-segment offset.
Two reasons: (1) CRC usage is reached through AUTOSAR **function-pointer vtables / config structs**,
so static tracing from the primitives to a data-flash loop doesn't resolve cleanly; (2) **the
8×16 KB / two-checksum layout is a DQ381 (Bosch) construct** — this ZF firmware uses AUTOSAR
**NvM/Fee** (variable blocks), so that fixed-segment structure may not exist here at all.

**INFERENCE:** the two per-segment checksums are almost certainly **CRC-16-CCITT + CRC-8/0x2F**
(the AUTOSAR E2E pair). Polys CONFIRMED; standard init/xorout (CCITT-FALSE init 0xFFFF / xorout 0;
H2F init 0xFF / xorout 0xFF) INFERRED, not shown — which is why the hunter carries all of these as
*candidates* rather than the toolkit asserting one.

**DQ381 note:** tried to cross-check on the DQ381 (Bosch) ASW — the actual home of the 8×16 KB
layout — but the repo's `odx.py` cannot currently extract DQ381 BL301: the FRF container + **AES
layer decrypt fine** (the block shows the same `876543` header as the ZF ASW), but
**`decompress_lzss` fails** (`IndexError`) on the block, so it falls through to `.encrypted`. The
ODX method is really `AA`, not `0A` as `docs/KEYS.md` states. Fixing DQ381 BL301 extraction (the
LZSS framing) is a separate, fix-worthy task — the README's "✅ Extractable" is optimistic for BL301.

## Status of the remaining pieces

- **DQ381 data checksum — DONE** (above; `core/checksum.py`). The owner-supplied 128 KB dump
  settled it directly; the hunter (`tools/eeprom_checksum_hunt.py`, with its CRC-8/0x2F battery)
  remains for other units/layouts.
- **DQ381 0x54 management word — open, and not needed for data edits.** Exhaustively not a data
  checksum (ruled out 7/7); it tracks the ring counter and is payload-independent. Its exact
  derivation would come from force-disassembling the EEL engine in the BOOT region
  (`0x10200-0x30200`) of the full flash dump — the data word-sum loop is now a known signature to anchor
  on, with the 0x54 computation adjacent.
- **ZF 8HP — different layout.** The ZF ASW is AUTOSAR **NvM/Fee** (variable blocks), not the
  8×16 KB EEL ring; its CRC primitives are pinned (table above) but the 8×16 KB / two-checksum
  construct is a DQ381 (Bosch) thing and may not exist there.

*This pass (uncommitted): `core/checksum.py` (+`eel_eeprom_validate` / `eel_eeprom_fix`), this doc.
Dump-validation + the 0x54 negative in the session scratchpad (`dq381_rar/EEL_CKSUM2_FINDINGS.md`,
`tcu/EEPROM_CKSUM_FINDINGS.md`).*
