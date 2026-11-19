# Third-party notices

This project contains code and data derived from the work below. Their notices
apply to those parts; the project's own licence (see `LICENSE`) covers the rest.

## lsdlsd88 / TCU-FRF-SGO-UNPACKER

The SGML Object File (`.sgo`) parser (`core/sgo.py`), the format-1 substitution
ciphers (`core/crypto_table.py` and the C hot loops in `core/sgo_fast.c` /
`core/sgo_fast.py`), and the recovered 256-byte family cipher tables
(`platforms/sgo_tables.py`) are ported from this project.

- Project: https://github.com/lsdlsd88/TCU-FRF-SGO-UNPACKER
- Licence: MIT

```
MIT License

Copyright (c) 2026 lsdlsd88

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

## calledit / SGML_Object_File_reader

The SGO v2 layout and parser originate with calledit's `SGML_Object_File_reader`
(`read_sgo.php`); lsdlsd88's Python port extended it for the DSG/CVT TCU files,
and this project ports that in turn.

- Reference: https://github.com/calledit/SGML_Object_File_reader

## bri3d / VW_Flash

The FRF container decryption and the LZSS/LZZ decompression references
(`core/frf.py`, `core/lzss.py`, `core/lzz.py`) derive from VW_Flash.

- Project: https://github.com/bri3d/VW_Flash
- Licence: BSD 2-Clause (the GPL-licensed `lzss/` subdirectory is not used)

## Recovered key material and cipher tables

`data/frf.key` and the substitution tables in `platforms/sgo_tables.py` were
recovered by reverse engineering, for interoperability only. They are not
anyone's intellectual property and are included solely because the containers
cannot be decoded without them.

## PyCryptodome

AES-128-CBC is provided by PyCryptodome (BSD 2-Clause, Legrandin and
contributors), installed from PyPI.
