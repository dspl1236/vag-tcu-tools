"""Optional ctypes loader for the compiled SGO table-cipher hot loops.

The shared library built from ``sgo_fast.c`` is optional: ``TableBlockCrypto``
imports this module, checks :func:`available`, and falls back to its pure-Python
implementation when the library is missing, so absence only costs speed.

Build it for the current platform with::

    python -m core.build_sgo_fast

Ported from lsdlsd88/TCU-FRF-SGO-UNPACKER ``sgo_fast.py`` (MIT), trimmed to the
two table ciphers this toolkit uses.
"""
import ctypes
import os
import sys
from pathlib import Path

_LIB = None
_TRIED = False

# Platform-appropriate shared-library names the loader will look for.
_NAMES = ("sgo_fast.dll", "libsgo_fast.so", "libsgo_fast.dylib", "sgo_fast.so")


def _candidates():
    env = os.environ.get("SGO_FAST_LIB")
    if env:
        yield Path(env)
    here = Path(__file__).resolve().parent
    for name in _NAMES:
        yield here / name
    bundle = getattr(sys, "_MEIPASS", None)
    if bundle:
        for name in _NAMES:
            yield Path(bundle) / name


def _configure(lib):
    for fn in ("sgo_table_decrypt", "sgo_feedback"):
        func = getattr(lib, fn)
        func.argtypes = [ctypes.c_char_p, ctypes.c_char_p,
                         ctypes.c_char_p, ctypes.c_size_t]
        func.restype = None


def load():
    """Load the shared library once; return the handle, or None if unavailable."""
    global _LIB, _TRIED
    if _TRIED:
        return _LIB[0] if _LIB else None
    _TRIED = True
    for path in _candidates():
        try:
            if not path.is_file():
                continue
            lib = ctypes.CDLL(str(path))
            _configure(lib)
            _LIB = (lib, str(path))
            break
        except (OSError, AttributeError):
            continue
    return _LIB[0] if _LIB else None


def available() -> bool:
    return load() is not None


def path():
    load()
    return _LIB[1] if _LIB else None


def table_decrypt(table_bytes: bytes, data: bytes) -> bytes:
    """SGO format-1 PQ/MQB cipher (progressive)."""
    lib = load()
    if lib is None:
        raise RuntimeError("sgo_fast shared library is not available")
    out = ctypes.create_string_buffer(len(data))
    lib.sgo_table_decrypt(bytes(table_bytes), bytes(data), out, len(data))
    return out.raw


def feedback(table_bytes: bytes, data: bytes) -> bytes:
    """Early 02EA byte-feedback cipher."""
    lib = load()
    if lib is None:
        raise RuntimeError("sgo_fast shared library is not available")
    out = ctypes.create_string_buffer(len(data))
    lib.sgo_feedback(bytes(table_bytes), bytes(data), out, len(data))
    return out.raw
