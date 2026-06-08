# VAG Flash Tools

Open-source toolkit for VW/Audi transmission firmware reverse engineering.
Covers multiple platforms sharing the Renesas SH72549 (SH-2A) MCU.

## Supported Platforms

| Platform | Encryption | Compression | Status |
|---|---|---|---|
| **DQ381.2** (BL301) | AES-128-CBC | LZSS (1023) | ✅ Fully extractable |
| **DQ381.2** (BL401) | AES-128-CBC | LZSS | ⚠️ Key unknown |
| **ZF 8HP** (method 22) | XOR 19-byte | LZZ (2047) | ✅ Fully extractable |
| **ZF 8HP** (method 01) | AES-128-CBC | None | ⚠️ Key unknown |

## What it does

- **FRF extraction** — Decrypt VW/Audi flashdaten containers → raw firmware
- **Multi-crypto** — AES-128-CBC (DQ381) and repeating XOR (ZF 8HP)
- **Multi-compression** — LZSS (1023 window) and LZZ (2047 window)
- **Checksum** — CRC32 validation and correction
- **Platform configs** — Flash layouts, SA2 scripts, calibration addresses

## Architecture

```
core/               Shared infrastructure
  frf.py            FRF container decrypt (rolling XOR, all platforms)
  odx.py            ODX/ODX-F parser (inline + external .bin)
  crypto_aes.py     AES-128-CBC (DQ381, Simos)
  crypto_xor.py     Repeating XOR (ZF 8HP)
  lzss.py           LZSS 1023-byte window (DQ381)
  lzz.py            LZZ 2047-byte window (ZF 8HP)
  checksum.py       CRC32 / CRC-CCITT

platforms/
  dq381/            DQ381 keys, flash layout, scanner addresses
  zf8hp/            ZF 8HP keys, memory map, variant database

docs/
  KEYS.md           All known encryption keys (single reference)
  PLATFORM_RESEARCH.md  SH72549 boot mode, flash protocol, hardware
```

## Key Findings

### DQ381 AES Key Storage

The bootloader stores its AES key/IV at a fixed offset, confirmed across
all four extractable BL301 variants:

```
BOOT offset 0x344: IV  (16 bytes)  →  flash address 0x010544
BOOT offset 0x354: Key (16 bytes)  →  flash address 0x010554
```

### ZF 8HP XOR Key

The ZF 8HP (method 0x22) uses a 19-byte repeating XOR cipher — not AES:

```
Key: CyA2008ZFVAGtcuxsam
Hex: 437941323030385a465641477463757873616d
```

Verified: 1,310,208 bytes perfect match.  Works across A6/A7 C7 (4G0)
and A8 D4 (4H1) families — 400+ FRFs in the Audi flashdaten.

### LZZ Compression (ZF 8HP)

Variant of LZSS with inverted flag bits and larger window:
- Flag bit 0 = literal, 1 = back-reference (inverted from LZSS)
- Reference: 5-bit count (raw) + 11-bit displacement
- Window: 2047 bytes (vs LZSS 1023)

## Acknowledgments

- **[bri3d/VW_Flash](https://github.com/bri3d/VW_Flash)** (MIT) — FRF
  pipeline, DQ381 crypto, LZSS, SA2 research
- **[NefMoto community](http://nefariousmotorsports.com/forum/)** — SA2
  opcodes, VAG AES key research, decades of VW/Audi RE
- **chrisgotboost** (NefMoto) — ZF 8HP encryption key discovery, LZZ
  compression identification
- **projectLSaudiA4** (NefMoto) — AL551 memory map from A2L, Ghidra
  SH-2A disassembly, PCMflash Module 82 research
- **Renesas** — SH7254R Hardware Manual, SH-2A Programming Manual

## License

MIT
