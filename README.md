# VAG TCU Tools

Open-source toolkit for VW/Audi transmission control unit (TCU) firmware
reverse engineering.  Covers multiple platforms sharing the Renesas SH72549
(SH-2A, big-endian) MCU — including the Bosch DQ381 DSG and ZF 8HP
automatic families.

Built to give back to the community that made this research possible.

## Supported Platforms

| Platform | Vehicles | Encryption | Status |
|---|---|---|---|
| **DQ381.2** BL301 | MK8 GTI, Golf R, 8Y S3, Tiguan | AES-128-CBC | ✅ Extractable |
| **DQ381.2** BL401 | 2022+ MK8 GTI/R, S3 | AES-128-CBC | ⚠️ Key unknown |
| **ZF 8HP** method 22 | A6/A7 C7, A8 D4 | 19-byte XOR | ✅ Extractable |
| **ZF 8HP** method 01 | A4/A5 B8 | Byte-level (not AES) | ⚠️ Key unknown |

The same SH72549 MCU is also found in ZF 8HP45/50/55/70/75/90/95 across
BMW, Alfa Romeo, Dodge/Ram, Jeep, Maserati, Rolls Royce, and Aston Martin.
Gen3 ZF 8HP (post-2020) moved to Infineon TC275 TriCore.

## Features

- **FRF extraction** — Decrypt VW/Audi flashdaten `.frf` containers into raw
  BOOT/ASW/CAL binary blocks
- **Multi-crypto support** — AES-128-CBC (DQ381/Simos) and repeating XOR (ZF 8HP)
- **Multi-compression** — LZSS (1023-byte window) and LZZ (2047-byte window)
- **ODX + ODX-F parsing** — Handles both inline hex (BL301) and external `.bin`
  (BL401) flashdaten formats
- **CRC32 checksum** — Validate and correct DQ381 CAL block checksums
- **Platform configs** — Flash layouts, SA2 scripts, calibration addresses,
  variant databases

## Key Discoveries

### ZF 8HP Encryption — XOR, Not AES

The ZF 8HP TCU firmware (ODX method `0x22`) uses a simple 19-byte repeating
XOR cipher — not AES:

```
Key: CyA2008ZFVAGtcuxsam
Hex: 437941323030385a465641477463757873616d
```

Verified against real firmware with a **1,310,208-byte perfect match**.
Confirmed working across multiple Audi platform families (4G0, 4H1) covering
400+ FRFs in the official flashdaten.

### LZZ Compression Format

The ZF 8HP compression (method `0x22`) is a variant of LZSS with:
- **Inverted flag bits** — `0` = literal byte, `1` = back-reference
  (opposite of standard LZSS)
- **5-bit count + 11-bit displacement** (vs LZSS 6+10)
- **2047-byte sliding window** (vs LZSS 1023)

Reverse-engineered from scratch and verified byte-perfect against known
plaintext.

### DQ381 AES Key Storage

The DQ381 bootloader stores its AES-128-CBC key and IV at a fixed offset
in the BOOT block, confirmed across all four extractable BL301 firmware
variants:

```
BOOT offset 0x344: IV  (16 bytes)  →  flash address 0x010544
BOOT offset 0x354: Key (16 bytes)  →  flash address 0x010554
```

This means a 32-byte read from any BL401 DQ381 TCU at flash address
`0x010544` recovers the BL401 encryption key.

### DQ381 Calibration Map

Confirmed addresses from cross-variant analysis (FWD GTI vs Golf R, same
SW generation, 3.7% byte difference = pure calibration):

| Parameter | Offset | Stock GTI |
|---|---|---|
| Torque cap (Drive) | `0x28138` | 400 Nm |
| Torque cap (Sport) | `0x32138` | 400 Nm |
| Clutch clamping (Drive) | `0x20A80` | 500→201 Nm |
| Clutch clamping (Sport) | `0x2AA80` | 500→201 Nm |
| Rev limiter primary | `0x0333A` | 7000 RPM |
| Per-gear rev limits | `0x27CF8` | 6425 RPM × 7 |
| Shift schedule axes | `0x068B0` | 6 gears × 5 pts |
| Launch control RPM | `0x1CC46` | — |
| Speed limiter | `0x04E4E` | — |

Drive/Sport mode sections are duplicated at ~0xA000 offset in the CAL block.

## Project Structure

```
core/                   Shared infrastructure
  frf.py                FRF container decrypt (all platforms)
  odx.py                ODX/ODX-F flash block parser
  crypto_aes.py         AES-128-CBC
  crypto_xor.py         Repeating XOR
  lzss.py               LZSS (1023 window, DQ381)
  lzz.py                LZZ (2047 window, ZF 8HP)
  checksum.py           CRC32 / CRC-CCITT

platforms/
  dq381/                Keys, flash layout, scanner addresses
  zf8hp/                Keys, memory map, variant database

docs/
  KEYS.md               All known keys — single reference
  PLATFORM_RESEARCH.md  SH72549 boot mode, Renesas datasheet findings

tools/
  recover_aes_key.py    Key verification against known plaintext
```

## Installation

```bash
pip install -e ".[dev]"
pytest -q
```

## All Known Keys

See **[docs/KEYS.md](docs/KEYS.md)** for the complete reference including
DQ381, ZF 8HP, Simos ECU keys, SA2 scripts, and the FRF container key.

## Boot Mode Protocol

The SH72549 hardware boot mode (shared by DQ381 and all ZF 8HP variants)
uses SCI serial on pins PJ5/PJ6 with a key code authentication step.
Full protocol documented in
**[docs/PLATFORM_RESEARCH.md](docs/PLATFORM_RESEARCH.md)** based on the
Renesas SH7254R Hardware Manual (R01UH0480EJ0400) and SH-2A Programming
Manual (REJ09B0051).

## Contributing

This project exists because people shared what they knew.  If you have:
- A raw bench read from any BL401 DQ381 TCU (32 bytes at `0x010544` = the key)
- Encryption keys for other VAG TCU platforms (DQ500, DL501, DL382)
- Calibration address maps or A2L/DAMOS definitions
- Corrections to anything documented here

Open an issue or PR — or reach out on NefMoto/VWVortex.

## Acknowledgments

- **[bri3d/VW_Flash](https://github.com/bri3d/VW_Flash)** (MIT) — FRF
  decryption, DQ381 AES/LZSS implementation, SA2 seed/key research
- **[NefMoto community](http://nefariousmotorsports.com/forum/)** — SA2
  opcode documentation, VAG AES key research, and decades of open VW/Audi
  reverse engineering
- **chrisgotboost** (NefMoto) — ZF 8HP encryption key discovery and LZZ
  compression identification
- **projectLSaudiA4** (NefMoto) — AL551 memory map from A2L, Ghidra SH-2A
  disassembly, PCMflash Module 82 research, immobilizer RE work
- **crystal_imprezav & gremlin** (NefMoto) — VAG AES key trading and
  community knowledge sharing
- **Renesas** — SH7254R Hardware Manual and SH-2A Programming Manual

## License

MIT
