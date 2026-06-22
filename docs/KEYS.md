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

Applies to (Audi flashdaten — confirmed):
- 4G0927158 — A6/A7 C7 (EV_TCMAL551211)
- 4G1927158 — A6/A7 C7 variant (EV_TCMAL551211)
- 4H1927158 — A8 D4 (EV_TCMALX51011)
- 8K0927158 — A4/A5 B8 ZF 8HP (EV_TCMAL551211) — NOT to be confused with 8K0927155 (VL381)
- 8K1927158 — A4/A5 B8 variant (EV_TCMAL551211)
- 8R0927158 — Q5 8R ZF 8HP (EV_TCMAL551211) — NOT to be confused with 8R0927156 (DL501)
- 8R1927158 — Q5 8R variant (EV_TCMAL551211)

Applies to (Bentley flashdaten — confirmed):
- 3W0927158 — Continental GT (EV_TCMAL450211)
- 3W3927158 — Continental GTC (EV_TCMAL450211)
- 4W0927158 — Bentayga (EV_TCMAL450211)
- 3Y0927158 — Flying Spur (EV_TCMALX51011)

Note: AL450 (EV_TCMAL450211) is a ZF 8HP variant found only in Bentley
flashdaten — same XOR key, same LZZ format as AL551/ALX510.

Total method 0x22 coverage: ~560 FRFs across Audi + Bentley.

**Critical part number traps:**
```
8K0927155 = VL381 Multitronic CVT (TriCore) — NOT ZF 8HP
8K0927158 = ZF 8HP AL551 (SH72549)          — YES ZF 8HP ← same prefix, different box

8R0927156 = DL501 S-Tronic (TriCore)        — NOT ZF 8HP
8R0927158 = ZF 8HP AL551 (SH72549)          — YES ZF 8HP ← same prefix, different box
```

### Method 0xAA — AES-128-CBC + LZSS (key UNKNOWN)

Used by 4M0927158 (Q7/Q8 4M), 8W0927158 (B9 S4/S5/SQ5/RS4/RS5),
36A927158 (Bentley Bentayga older), 4M8927158 (SQ8/RS Q8),
4N0927158 (Q8/A7 C8), and 80A927158 (Q5 FY).
All confirmed EV_TCMALX52011_002 via ODX — same platform, same AES key.

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

### Method 0x01 — 256-byte Permutation Table Cipher (key/table UNKNOWN)

Used by: DL381 (0AW), VL381 Multitronic CVT (8K0927155), and others.

**Cipher algorithm** (confirmed by community RE — gremlin @ NefMoto, June 2026):
- 256-byte lookup table (values 0-255 in swapped order)
- Add/shift operations — NOT XOR, NOT AES
- Different table per TCU family (DL381 ≠ DL501)

8K0927155 (A4/A5 B8) was initially misclassified as ZF 8HP but is actually
VL381 Multitronic CVT on Infineon TriCore TC1766:
- ODX ECU variant: `EV_TCMVL381_A01`
- Confirmed from bench flash dump (8K0927155AF, 0x180000 bytes)

### Method 0x11 — Same Table Cipher + LZZ Compression

Used by: DQ200, DQ250, DQ400, DL501, DL382, and some DL800 (4T0 Huracan).
Same 256-byte permutation table algorithm as method 0x01 with LZZ compression
on top (same LZZ format as ZF 8HP method 0x22).

**Warning — Fake 0x11 variant (verified from Audi + Lamborghini flashdaten, June 2026):**
Some DL800 / DQ500 units (4S0927155xx, Audi R8) report method `0x11` in ODX
but actually use AES decryption.

Diagnostic: block alignment is the definitive test:
```
NOT 16-byte aligned  →  Real 0x11 (table cipher + LZZ)
16-byte aligned      →  Fake 0x11 (real AES)
```

Confirmed real 0x11 (Lamborghini flashdaten, EV_TCMDL800421):
  4T0927109A/_ (Huracan):
    FD_2: 13,982 bytes — NOT 16B-aligned, entropy 7.956
    FD_4: 199,423 bytes — NOT 16B-aligned, entropy 7.963
    FD_2 first 8 identical across all variants: 572cee9611104f48

Confirmed fake 0x11 / real AES (Audi flashdaten, EV_TCMDQ500021):
  4S0927155B/S (R8):
    FD_2: 703,232 bytes — 16B-aligned, entropy 7.956
    FD_3: 46,992 bytes — 16B-aligned, entropy 7.959
    FD_2 first 8 identical across all variants: df95e2430be70da7

Note: R8 FRFs carry both EV_TCMDL800041 and EV_TCMDQ500021 in ODX —
a combined DL800+DQ500 file, not a pure DL800 image.

Source: gremlin (NefMoto) + verified from Audi + Lamborghini flashdaten, June 2026.

### Method 0xA0 — UNKNOWN (Bentley 3SD/3SE)

Used by: 3SD927155/158 and 3SE927153/155/158 (Bentley Flying Spur/Continental).
Blocks NOT 16-byte aligned, entropy 5.3–6.5 (lower than AES — may be
compressed plaintext or a different cipher).  No ODX ECU variant found —
these FRFs may use a proprietary Bentley format.

Nothing further known.  Not related to any Audi/VW encryption method.

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
| DQ250 (MQB) | `68028149680593A55A55AA4A0587810595268249845AA5AA558703F780384C` |
| DL501 (S-Tronic) | `6805824A05870B5A4C1D2E3F4A5B494C` |
| ZF 8HP AL551/ALX510 | `6805824A10680284100819734A05872506200382499318111973824A058712082001824A0181494C` |
| ZF 8HP ALX520/AL552 | `680893231003DE4A0B680E814987FA2515786B096804824987BF72D54849845A23F1974C` |

Sources: bri3d/VW_Flash, community UDS scans, FRF ODX extraction.

## Simos ECU Keys (reference)

From bri3d/VW_Flash and community research:

| Platform | Key | IV |
|---|---|---|
| Simos12 (SC1) | `314d7536416e3047396a413252356f45` | `306e37426b6b536f316d4a6974366d34` |
| Simos12.2 (SC2) | `41326D3F50613D306C4C36616E346721` | `70493465726345296470557333235379` |
| Simos18 (SC8) | `98D31202E48E3854F2CA561545BA6F2F` | `E7861278C508532798BCA4FE451D20D1` |
| Simos18.10 | `AE540502E48E3854DBCA1A1545BA6F33` | `62F313FA5C08532798BCA452471D20D5` |
| Simos18.41 (TTRS) | `6E3FE03619F138798CB4ECDCC762005F` | `000102030405060708090A0B0C0D0E0F` |
