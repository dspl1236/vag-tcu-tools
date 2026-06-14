# SH72549 / SH-2A Platform Research

## Overview

The Renesas SH72549 (SH-2A core, big-endian) is the MCU used in both the
Bosch DQ381 DSG TCU and the ZF 8HP automatic transmission TCU. This document
tracks what's known about each platform's firmware encryption, flash layout,
and unlock mechanisms.

## Confirmed SH72549 Platforms

### Bosch DQ381.2 / ALx52 (DSG 7-speed, transverse)

| Property | Value |
|---|---|
| MCU | Renesas SH72549 (R5F72549) |
| Architecture | SH-2A, 32-bit, big-endian |
| VW PN prefix | 0GC906555 (FWD), 0GC906556 (AWD), 0GC906557 (R/S) |
| HW PN | 0GC927373L |
| Platform ID | MTFP DQ381, 1137D22_VW_DQ380 |
| CAN IDs | TX 0x7E1 / RX 0x7E9 |
| Vehicles | MK8 GTI, Golf R, 8Y A3/S3, Tiguan, Cupra Formentor |

**BL301 (Gen1) Flash Layout:**
- Block 1 BOOT: base 0x010200, length 0x01FE00 (130,560 bytes)
- Block 2 ASW:  base 0x030200, length 0x10FE00 (1,113,600 bytes)
- Block 3 CAL:  base 0x140200, length 0x03FE00 (261,632 bytes)
- Full BIN: 0x180000 (1,572,864 bytes)

**BL301 Crypto:**
- FRF container: recursive XOR cipher (frf.key)
- Flash blocks: AES-128-CBC
  - Key: `000102030405060708090A0B0C0D0E0F` (trivial sequential)
  - IV:  `101112131415161718191A1B1C1D1E1F` (trivial sequential)
- Compression: LZSS (6-bit count + 10-bit displacement, big-endian)
- ODX method: `0A` (encryption type A + no compression flag)
- Checksum: CRC32 (zlib), big-endian, stored at CAL offset 0x44
- SA2 script: `6806814A05876B5F7DD5494C`

**BL401 (Gen2) Flash Layout:**
- Significantly larger blocks: BOOT ~278KB, ASW ~2.6MB, CAL ~786KB
- ODX-F format with separate .bin files (not embedded in XML)
- Common .bin header: `ff0f417ffca39561e158d1fc894d38c7`
- AES key: **UNKNOWN** (different from BL301)
- SA2 script: `9390783612680B814A07872956814F6B05876BEE2005828490783612494C`
- ALFID: `0141`

**Confirmed CAL Addresses (BL301, 0GC906555_3260):**
- Torque cap table: 0x28138 (Drive), 0x32138 (Sport) — 400 Nm stock GTI
- Clutch clamping map: 0x20A80 (Drive), 0x2AA80 (Sport) — 500→201 Nm
- Rev limiter primary: 0x0333A — 7000 RPM
- Rev limiter secondary: 0x04B66 — 7000 RPM
- Per-gear rev limits: 0x27CF8 — 6425 RPM
- Shift schedule RPM axes: 0x068B0–0x06908 (6 gears × 5 breakpoints)
- Launch control RPM: 0x1CC46
- Launch control torque: 0x1C3E6
- Speed limiter axis: 0x04E4E
- Torque axis breakpoints: 0x018B4 [200,300,400,500,600]

**Cross-variant findings (555P FWD vs 557E Golf R):**
- Only 3.7% byte difference (same SW generation 4161/4162)
- Golf R has +640 to +2240 RPM higher shift points
- Different clutch clamping values
- AWD-specific parameters at 0x1B660 (Haldex coupling)

---

### ZF 8HP (8-speed automatic, longitudinal)

| Property | Value |
|---|---|
| MCU (Gen 1/2) | Renesas SH72549 (R5F72549) |
| MCU (Gen 3) | Infineon TC275/TC277 (TriCore) |
| Architecture | SH-2A (Gen1/2) or TriCore (Gen3), both big-endian |
| Audi PN prefixes | 8K0927155 (A4/A5 B8), 4G0927153 (A6/A7 C7), 4H1927158 (A8 D4), 8R0927156 (Q5 8R), 4K0927153 (A6/A7 C8), 8W0927155 (A4/A5 B9) |

**Variants (SH72549 era):**
- 8HP45: ≤450 Nm — BMW 1/2/3/4/5 Series, Alpina
- 8HP50: ≤500 Nm — BMW, Alfa Romeo
- 8HP55: ≤550 Nm — BMW, Audi
- 8HP70: ≤700 Nm — BMW 5/7 Series, Dodge Ram, Jeep, Maserati
- 8HP75: ≤750 Nm — Alfa Romeo, BMW
- 8HP90: ≤900 Nm — BMW 7 Series, Rolls Royce
- 8HP95: ≤900 Nm — Aston Martin

**Variants (TC275/TriCore era — covered by TriCoreTool):**
- 8HP51, 8HP76: BMW/JLR/Porsche (post-2020)

**ZF 8HP Crypto — Updated with community RE findings:**

Method 0x22 (AL551/ALX510 — 4G0, 4H1):
- 19-byte repeating XOR key `CyA2008ZFVAGtcuxsam` — CRACKED ✅
- LZZ compression (inverted flags, 5-bit count, 11-bit displacement)

Method 0xAA (ALX520/AL552 — 4M0, 8W0):
- Real AES-128-CBC (confirmed: 16-byte aligned blocks)
- Key UNKNOWN — bench read needed

**Warning — Other platform methods explained (gremlin @ NefMoto, June 2026):**
Method 0x01 (DL381/VL381): 256-byte permutation table + add/shift algo, NOT XOR
Method 0x11 (DQ200/DQ250/DQ400/DL501/DL382): same table algo + compression
Method 0xAA "fake" (DL800 R8/Huracan): table cipher despite 0xAA marking

**Audi Flashdaten Corpus:**
- 1,365 ZF 8HP TCU FRFs across all longitudinal Audi platforms
- A4/A5 B8: 366 FRFs
- A6/A7 C7: 289 FRFs
- Q5 8R: 191 FRFs
- A8 D4: 116 FRFs
- A4/A5 B9: 109 FRFs
- A6/A7 C8: 79 FRFs
- Q5 FY: 70 FRFs
- Q7/Q8: 49 FRFs

---

## Reference Documents

- **Renesas SH7254R Hardware Manual** — Document R01UH0480EJ0400 (1,848 pages)
- **Renesas SH-2A/SH2A-FPU Programming Manual** — Document REJ09B0051

Search these document numbers on the Renesas website or engineering archives.

## Boot Mode Protocol (SH72549, all platforms)

Source: Renesas SH7254R Hardware Manual, Section 25.5

The hardware boot mode is identical across DQ381 and ZF 8HP since they
share the same MCU silicon:

1. Enter boot mode via mode pins (MD2:MD0 = 110)
2. SCI serial connection on PJ5 (TxD_A) and PJ6 (RxD_A)
3. Bit rate auto-negotiation
4. Device/clock inquiry and selection
5. **Key code detection**: command `H'40`, response `H'16`
6. **Key code check**: command `H'60` + size + key data + checksum
   - Key matches → response `H'26` → **full erase** → programming mode
   - Key mismatch → response `H'E0`
   - Key in initial state (blank) → `H'26` to ANY key
7. NMI/IRQ must be held non-active during boot mode
8. AUD-II debug interface (Section 21) is separate from boot mode

Commercial bench tools (AutoTuner, Unitronic, 034 Motorsport, Flex)
connect to SCI pins via bench harness. The "Bench NR" (non-read) mode
aligns with boot mode's full-erase-on-key-match behavior.

---

## Extraction Pipeline Status

| Step | DQ381 BL301 | DQ381 BL401 | ZF 8HP |
|---|---|---|---|
| FRF decrypt | ✅ | ✅ | ✅ |
| ODX parse | ✅ (ODX) | ✅ (ODX-F) | ✅ (ODX) |
| Block identify | ✅ | ✅ | ✅ |
| AES decrypt | ✅ (key known) | ❌ (key unknown) | ❌ (key unknown) |
| LZSS decompress | ✅ | N/A | N/A (no compression) |
| CRC32 checksum | ✅ | untested | unknown |
| Scanner | ✅ (26 tests) | blocked | blocked |

## FRF Corpus Summary

**VW Flashdaten (2024):**
- DQ381 TCU software: 13 FRFs (4 extractable BL301, 9 BL401)
- DQ381 mechatronics: 260 FRFs

**Audi Flashdaten (2024):**
- DQ381 (0GC): 68 FRFs
- ZF 8HP TCU: 1,365 FRFs (AES key unknown)
- Other transmissions: DQ200 (0CW, 145), DL382 (0BH, 49), DQ500 (0D9, 53)

Total transmission FRFs available: **1,899**
