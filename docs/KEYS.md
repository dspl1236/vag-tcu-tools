# Known VAG Transmission Encryption Keys

Single reference for every encryption method and key across VAG
transmission platforms.  All keys verified against real firmware.

## DQ381.2 / ALx52 (Bosch, SH72549)

### BL301 (Gen1) — AES-128-CBC

```
Key: 000102030405060708090A0B0C0D0E0F
IV:  101112131415161718191A1B1C1D1E1F
```

- ODX method: `0A` (encryption A + LZSS compression via DSG flag)
- Compression: LZSS (6-bit count + 10-bit displacement, 1023 window)
- Stored in BOOT block at offset 0x344 (IV) / 0x354 (Key)
- Flash address: 0x010544 (IV) / 0x010554 (Key)
- Confirmed across 4 firmware variants (555/557, SW 3260/4161/4162/4260)
- Source: bri3d/VW_Flash (MIT)

### BL401 (Gen2) — AES-128-CBC (key UNKNOWN)

- ODX-F method: `AA` (AES encryption + LZSS compression)
- Key stored at same BOOT offset (0x344/0x354) in plaintext on flash
- 32-byte read at flash address 0x010544 from any BL401 TCU recovers it
- Common .bin header: `ff0f417ffca39561e158d1fc894d38c7`
- SA2: `9390783612680B814A07872956814F6B05876BEE2005828490783612494C`
- All known VW Group AES keys tested — none match

## ZF 8HP (ZF Friedrichshafen, SH72549)

### Method 0x22 — Repeating XOR + LZZ

```
Key: CyA2008ZFVAGtcuxsam
Hex: 437941323030385a465641477463757873616d
```

- 19-byte repeating XOR cipher (NOT AES)
- ODX method: `22` (LZZ compression + XOR encryption)
- Compression: LZZ (inverted flags, 5-bit count + 11-bit displacement, 2047 window)
- Verified on 4G0927158BE (A6/A7 C7, 1,310,208 bytes PERFECT MATCH)
- Confirmed working on 4H1927158AD (A8 D4 8HP90)
- Applies to: 4G0 (A6/A7 C7, 289 FRFs) + 4H1 (A8 D4, 116 FRFs) = 400+ FRFs

### Method 0xAA — AES-128-CBC + LZSS (key UNKNOWN)

Used by 4M0927158 (Q7/Q8 4M) and 8W0927158 (B9 S4/S5/SQ5/RS4/RS5).
Both share ODX variant `EV_TCMALX52011_002` — same platform, same key.
Community names: ALX520 (Q7/Q8) and AL552 (B9 S/RS) = same hardware.

Same SH72549 MCU as method 0x22 variants, but newer bootloader using
Bosch standard AES encryption (same scheme as DQ381 BL301).

- 5 flash blocks, all 16-byte aligned (AES)
- Cross-variant XOR confirms same key across 4M0 and 8W0 families
- FD_05 (16,160 bytes) is byte-identical across all variants
- FD_03 (BOOT, 120,240 bytes) same size and first 16 bytes across all
- SA2 script: `680893231003DE4A0B680E814987FA2515786B09...`
- Neither BL301 trivial key nor CyA XOR key works
- AES key likely at similar BOOT offset as DQ381 (bench read needed)
- ~58 FRFs total: 4M0 (~33) + 8W0 (25)

Note: 8W0927**155** = DL-382 (EV_TCMDL382021, different transmission!)
      8W0927**158** = AL552/ALX520 (EV_TCMALX52011, ZF 8HP)

### ~~Method 0x01~~ — NOT ZF 8HP (CORRECTED)

8K0927155 (A4/A5 B8) was initially classified as ZF 8HP but is actually
**VL381 Multitronic CVT** on Infineon TriCore TC1766:

- ODX ECU variant: `EV_TCMVL381_A01` (not ZF 8HP)
- Firmware strings: `VL381 Tricore 1766`, `EV_TCMVL381`
- Confirmed from bench flash dump (8K0927155AF, 0x180000 bytes)
- Same TriCore platform as DL501 (see below)
- Uses trivial AES key `000102...0F` at flash offset ~0x05F000

The actual ZF 8HP in the A4/A5 B8 (quattro models) uses different part
numbers.  All confirmed ZF 8HP FRFs (4G0, 4H1) use method 0x22 (XOR).

## DL501 / VL381 (Borg Warner, TriCore — reference only)

**Not in scope for this repo** (TriCore TC1766, not SH72549), but
documented here for community reference.

```
Key: 000102030405060708090A0B0C0D0E0F (same trivial key as DQ381 BL301)
Location: flash offset 0x05E674 (confirmed from bench read)
MCU: Infineon TriCore TC1766
Platform: "VL381 Tricore 1766"
Flash size: 0x180000 (1,572,864 bytes)
```

- Same trivial sequential AES key as DQ381 BL301 — suggests this was a
  common Bosch default across multiple VAG transmission families
- BCM2 pairing uses Renesas 70F3380 (V850 family) with WFS5 immobilizer
- EEPROM: 8,192 bytes (0x2000)

## FRF Container

All VAG flashdaten .frf files share the same container encryption:

```
Type: Rolling XOR cipher
Key:  data/frf.key (4095 bytes)
```

Source: bri3d/VW_Flash (MIT).  Universal across all VW Group platforms.

## SA2 Seed/Key Scripts

SA2 is the universal VAG OBD authentication mechanism.  Scripts are
bytecode programs for a tiny VM.  See bri3d/sa2_seed_key.

| Platform | SA2 Script |
|---|---|
| DQ381 BL301 | `6806814A05876B5F7DD5494C` |
| DQ381 BL401 | `9390783612680B814A07872956814F6B05876BEE2005828490783612494C` |
| ZF 8HP (4G0) | `6802814993A55A55AA4A05878105952668058249845AA5AA558703F7805C4C` |
| ZF 8HP (simos-suite) | `6805824A10680284100819734A05872506200382499318111973824A058712082001824A0181494C` |

## Simos ECU Keys (reference)

From bri3d/VW_Flash and dspl1236/simos-suite:

| Platform | Key | IV |
|---|---|---|
| Simos12 (SC1) | `314d7536416e3047396a413252356f45` | `306e37426b6b536f316d4a6974366d34` |
| Simos12.2 (SC2) | `41326D3F50613D306C4C36616E346721` | `70493465726345296470557333235379` |
| Simos18 (SC8) | `98D31202E48E3854F2CA561545BA6F2F` | `E7861278C508532798BCA4FE451D20D1` |
| Simos18.10 | `AE540502E48E3854DBCA1A1545BA6F33` | `62F313FA5C08532798BCA452471D20D5` |
| Simos18.41 (TTRS) | `6E3FE03619F138798CB4ECDCC762005F` | `000102030405060708090A0B0C0D0E0F` |
