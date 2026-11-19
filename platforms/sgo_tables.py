"""Recovered 256-byte cipher tables for VAG DSG / CVT SGO "format 1" blocks.

These substitution tables were recovered by reverse engineering, for
interoperability, by reading them out of TCU firmware (the flash offset is
noted per entry where upstream recorded it). They are not anyone's
intellectual property and are included only because the containers cannot be
decoded without them.

Source: lsdlsd88/TCU-FRF-SGO-UNPACKER (MIT) -- sgo_tables.py and sgo_early.py.
Applied by core.crypto_table.TableBlockCrypto; the .sgo container is parsed by
core.sgo. Every table is a 256-byte permutation (checked in the tests).

See THIRD_PARTY_NOTICES.md for provenance.
"""

from core.crypto_table import TableBlockCrypto

TABLES = {
    # Temic VL381/0CK, DL382 (method 11) and 0B5/DL501 (method 01/11).
    'temic': bytes.fromhex(
        "d311f7943d7139e740be96440bf567b3587dc4f9a95ced6bd1abe801b7476c57"
        "cafe09ba5a060014289b7f4af195cee4cf3679769ee3eb6fbcc588bb9db4acbf"
        "849c13a2ddb87391599081f3fb3f0c4c03dc45626ecd1c20ea7e07e1b64db22f"
        "c072a621a14e4bfc0e2b12e6c256931e55506a300a0586ffcb1925c87befd851"
        "8963dee964e53ab1e034231da77443d738ee3754291bbd2731c670835d33ad65"
        "aada419a698af82ddfd95f48d05e167c61982cb51aa81f0d088f15c94292c180"
        "b93b8e993578b052534f68d65b87ec043e6da08c8da3f42a0f3cf2fa85d477c7"
        "7ad5a49ffd174966c360dbcc24f018d2aea526028b22e22e8297f6af10467532"),
    # DQ250-MQB wet 6-spd DSG (02E MQB; 5/11 LZZ + MQB SGO blocks).
    'mqb_dsg': bytes.fromhex(
        "4593ca72845d11e978b99fa265e28be5c977cd59f78901bf02f368e0dc30c4d4"
        "f525cc8723c8ee3a12ab70610041d30dc0f422afd1cbb0b715278fd909ac5cf2"
        "f1c72a21568c063508e7c3734939cf40436bc66eea906d1bb453d25fb67416d7"
        "2b975a8a58c53375fcad3b60ce62912d0c3cda42269283fa182832074abb542c"
        "b89d4ce4a4715ea7ed2f377634d8c18e44636451f61ec2f8690adfe6f99e4ea8"
        "ff889a5b0f1f3f24e3fe9bb3a58086961d50de04a6553d059ceb8db5ef946c31"
        "a02014134f66f02946bdd64bdbbe360b85a1b2b11910fd1c81e10e7da9e847d5"
        "1a035738bcae98fbaa7e6a526f17a3677a7bddec2e3e7f7c48d099ba79954d82"),
    # DQ200-MQB 0CW dry 7-spd DSG, software 5xxx/6xxx.
    'dq200mqb': bytes.fromhex(
        "be0eb8584ce6ead4e9223e002801cad37c66dd041e9398492131ebb0380b82ba"
        "571516f330ac8f1467797513331a0581b3f0703c642f17f9d62cda6fc3bd6072"
        "40facc07363a4d4255a7c2eee5c05c41201d0a926e5e459761e3abbc9cd0068e"
        "ad9f8a73ed77445ab1194a630f2dff9a39f46c90592e53a8629b5ffe2bfd2978"
        "4e8d37e27f02b7d2decb7eae52e8fb802aef0d4fec5b468c7b832748517a096a"
        "23266da9c8b5108b0887aa1256c1346b183f886965afd885df9de01cb9d7a51f"
        "c5991143dba6f53591e11be7f25095bba371b2c6ce9e3d3b47dc84c47df7f15d"
        "68b40cc9d1f85489f6fc0374cdcfd9d586b6bf76a424a196a2e494c7a04b2532"),
    # DQ200-MQB 0CW, software 09xx-19xx (table read at flash 0x169A0).
    'dq200mqb_gen2': bytes.fromhex(
        "b0fbc45de4cc4d121779b5c963820ea07c9fc1a74002c84590dc1ed75f227499"
        "089126cae5f06d0b1d95d609bd2af35bb150aec6a81f922459e8e36b163f7821"
        "7b5af627054c653e76abdd859b7530520c131cbf0fceb86c67e223a64a6f9eee"
        "9355b984dfdeecbed343d219acaaa31b3456f74f18b77adac0d8c55106f5fa4e"
        "9670680a2ea43cd042cffff2bc8628942b32eac20166f9ad36e060629d00a2cd"
        "bb115c8714afc7737f4647fcf1b477d9a18df4cb07353983eb800d44fe413a9c"
        "4964d5726aef58d18fc3312d20892ce988a58b7e25572f33f88e61d4154b10e7"
        "5e69b6dbe6ed4897b2378a5438988c299ae103048153fd6e71ba3d7d3ba9b31a"),
    # DQ200 PQ legacy SGO format-1.
    'dq200_pq': bytes.fromhex(
        "657f83ad0040c49f4e30a910d6469cd5eb192c52314faf905d593c5e78dff774"
        "9e6b951684c1d3cc87ce43f9c8f83f0ded510c538c6a232aec8954a066038e39"
        "feae0aee37d18817a7bc969991bae7bdbff5e011b9a52b1ae96d28076fa65097"
        "24c6b55733c7e2d0a421e84df67e61155c793ab31c5582e1222fda703bead258"
        "933402d4ff0fb1c58f7bdc7cc2738bd90627a8a28056b7f2c3e32d6cde29f301"
        "44bbe58dcb4114c0becac9aa863d67491d7a205b9b9db2421277640b8a051b9a"
        "3ef0d8dbfd04f47d98cd60acb6b81ffa5acf3813724ae6a1b069fb7581a3f126"
        "efdd94451e32920e35b448fc4768082509632e6e5f364b18d785ab6276e44c71"),
    # DQ250 PQ (02E) wet 6-spd DSG.
    'dq250_pq': bytes.fromhex(
        "fab6c9aae801ea7f031c93dd22575e45d05fe6f05b70607636dc69b5ab2ab840"
        "1a1fc178614a9ae5d292914706242db75d0bcb37e056d52194a7bee988f7b48e"
        "3e34eb7e19a653d9684be386ca10a8466c67df30426b837426ec5cf2edfece7a"
        "9c7154f5aecf316a8f15d43577b3087cbd2e3f96114179fb8bc00aa309e26528"
        "14d152cc55395a27fdcdc70ef3899b8564828d9f59ac2f3af67db9af73480595"
        "2b1d4cdec432dbf9f43b1b026681ada4bf4f6313c6f100f80787973d12e1ee17"
        "a5b144dad8a98a72e46e84c3d66d51d775b24d58a19e25621820c81e980c80ba"
        "7b6f9d90b02950ef492c04c24ea2fca00fbcd3c53c16bb433833998cff0de723"),
    # DQ250C PQ variant.
    'dq250c_pq': bytes.fromhex(
        "10f8754fffa831fb9e2008f76cb58ed5bf32f2595c1cde453b8bf6d255345103"
        "3d4be0150d3953af3e2fa225f991faddcb6fa938c6fed657e86bef285e44637d"
        "3ae9d80ba1c25f9f50605bec9770624082bac8ebc5b7358d85a5a090476e1889"
        "9a8754cfea927e4156c15dc4ce0f991283849558cd1baa663364f1bd4dca0768"
        "f5b627b15ae52181c749b82bb3ee2dfce11e6d9cd74e22a60abee4c07411da93"
        "ab6a2cd07a16e700ed9d5261a30cf32a8c484c131772f4b2361ac3d97f049b8a"
        "7914057896427329d371b088373f65022ee306e630b9fdad98a41d8f24dbc943"
        "7c26dc1f947bb4f01980690109df86763caeacccbb0e23bcd4d14a7746e267a7"),
    # DQ400e 0DD hybrid DSG (table read at flash 0x1698C, after 'EV_TCM').
    'dq400e': bytes.fromhex(
        "feaa038c1f0ebaff4661ae9d3a588df1adef36ec1eb9c0d774be12e1c1e618d3"
        "7685f3776e3065045edd2c89887851e527353d7fdad573224d849b7e94a6c45a"
        "f50fd8e01057f200a7eb6847137519f8ac8b39e2cd52d682874cb4c36b4ffb0d"
        "edc8016dcad4c7977a9e7256cc86fa96a391dc205bc6cb9af0a16390b308dff7"
        "92a23e625434ce05ee5c605009805317328a931b2a7c4544b66948b859286ac9"
        "b1d241641ce83bd9291d1ab25fe7407b23c5cf4a6c33e42fb00abd3cd04eab2b"
        "98a9211566d1a007f62e16e9af9f26de67e3db8e0295fc8155f4ea0b3fb7fda5"
        "49bb38c2a87031bc8ff943839c0c2d112414a47942375dbf7d25b50699714b6f"),
    # VL381/0CK method-01 (8K0927155...); table at flash 0xA001017C.
    'vl381_01': bytes.fromhex(
        "6affc747f065ea1cf510fceda7c33c199bf7aaf2015f848d7855d05b33f4c258"
        "0a468eef8b2bdf38429631c9f97bcfb9fe125d5aca033b995ea38a8048669850"
        "a22e3495bdabb40dd1890b744ec0d6402c5ca4ba458c72186e289d26a1e1a0af"
        "098f753f9fb17ca9636b1767210f9302dc2391253eb7eee9d314222011bfbb2d"
        "e2057dbef81d076f6c94f3c144e8eb3a73a5cc9262292470b2d9ae3654cdb643"
        "4bb0b8089c4186c43037f14ae31f837ea852bc57ace7d2154c8800713927fd61"
        "db59da903d069a4fadd787e4492a51fae01b697735e6327f7a7985d8c50cc60e"
        "1eec68de1613f6e51ab5d46d82cb5697b353d5fbce2f9edd64a676604dc80481"),
    # Early DQ250 02EA format-1 (byte-feedback cipher, not progressive).
    'dq250_early': bytes.fromhex(
        "036840dfb959d1648401ce3c70ea8b0c52716a4765c950c376e7f96b5ab2ed1a"
        "e8a2b5b08c13ef14266680558d5c1df388a02dde6df4ebbce9163bddf1ae0f46"
        "985b6279d42e3a05f7cb5f354b810d30aa1ce2ee9196dbfab49da5c7776c18e1"
        "b629835e8faf3139459ccd22be0044bb93e3c47f92d9580acfd307bf4a4d2ff6"
        "367c42565404c0f2c61f25069b1048a44fe01551197e2bbd89024108a73e27a1"
        "69b1fde5baf56f756797d073782c0b3343e612b7856387fc604e3d86727b2334"
        "a809dc38f8c52049531137a9a67d17d20ec11bc8d7ff24d54cccf0a35d94fe57"
        "b3ad822a1efb99e4d69eb88a28d88eda9ac26eec32617495219f90acca3fab7a"),
}

# family identifier -> (table name, cipher mode, human description).
# "progressive" is the rolling-0x167 recurrence; "feedback" is the early
# 02EA (stored + previous) cipher. Methods are noted where upstream recorded
# them; a method label alone cannot always pick the family (see upstream
# frf_family.TABLE_METHODS), so the caller supplies the family.
FAMILIES = {
    "dl382":         ("temic",         "progressive", "DL382 7-spd S-Tronic (Temic; 8W0/4K0 ...155/153), method 11"),
    "dl501":         ("temic",         "progressive", "DL501 0B5 7-spd S-Tronic (Temic), method 01/11"),
    "vl381":         ("temic",         "progressive", "VL381 Multitronic CVT (Temic, 0CK)"),
    "vl381_m01":     ("vl381_01",      "progressive", "VL381/0CK method-01 containers (8K0927155...)"),
    "dq250mqb":      ("mqb_dsg",       "progressive", "DQ250 MQB wet 6-spd DSG (02E MQB)"),
    "dq200mqb":      ("dq200mqb",      "progressive", "DQ200 MQB dry 7-spd DSG 0CW, SW 5xxx/6xxx"),
    "dq200mqb_gen2": ("dq200mqb_gen2", "progressive", "DQ200 MQB 0CW, SW 09xx-19xx"),
    "dq200pq":       ("dq200_pq",      "progressive", "DQ200 PQ legacy SGO format-1"),
    "dq250pq":       ("dq250_pq",      "progressive", "DQ250 PQ (02E) wet 6-spd DSG"),
    "dq250cpq":      ("dq250c_pq",     "progressive", "DQ250C PQ variant"),
    "dq250_early":   ("dq250_early",   "feedback",    "Early DQ250 02EA format-1 (byte-feedback)"),
    "dq400e":        ("dq400e",        "progressive", "DQ400e 0DD hybrid DSG"),
}


def get_table(name: str) -> bytes:
    """Return the 256-byte table for `name` (a key of TABLES)."""
    try:
        return TABLES[name]
    except KeyError:
        raise ValueError(
            f"unknown cipher table {name!r}; known: {', '.join(sorted(TABLES))}"
        ) from None


def crypto_for(family: str):
    """Return a TableBlockCrypto for a FAMILIES key (its table + cipher mode)."""
    try:
        table_name, mode, _desc = FAMILIES[family]
    except KeyError:
        raise ValueError(
            f"unknown family {family!r}; known: {', '.join(sorted(FAMILIES))}"
        ) from None
    return TableBlockCrypto(get_table(table_name), mode)
