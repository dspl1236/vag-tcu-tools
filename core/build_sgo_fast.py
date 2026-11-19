"""Compile the optional ``sgo_fast`` acceleration library for this platform.

Usage::

    python -m core.build_sgo_fast

Writes the shared library next to ``sgo_fast.c`` (``sgo_fast.dll`` on Windows,
``libsgo_fast.so`` on Linux, ``libsgo_fast.dylib`` on macOS). This is OPTIONAL:
the toolkit works without it, only slower. Tries MSVC ``cl`` then ``gcc``/
``clang`` on Windows, and ``cc``/``gcc``/``clang`` elsewhere.
"""
import shutil
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
SRC = HERE / "sgo_fast.c"


def _run(cmd):
    print("  $", " ".join(cmd))
    return subprocess.run(cmd, cwd=HERE, check=False).returncode == 0


def build() -> Path | None:
    if not SRC.is_file():
        print(f"missing source: {SRC}", file=sys.stderr)
        return None

    if sys.platform == "win32":
        out = HERE / "sgo_fast.dll"
        if shutil.which("cl") and _run(
            ["cl", "/nologo", "/O2", "/LD", str(SRC), f"/Fe:{out}"]
        ):
            return out
        for cc in ("gcc", "clang"):
            if shutil.which(cc) and _run(
                [cc, "-O2", "-shared", "-o", str(out), str(SRC)]
            ):
                return out
        print("no working compiler found (tried cl, gcc, clang)", file=sys.stderr)
        return None

    out = HERE / ("libsgo_fast.dylib" if sys.platform == "darwin" else "libsgo_fast.so")
    for cc in ("cc", "gcc", "clang"):
        if shutil.which(cc) and _run(
            [cc, "-O2", "-fPIC", "-shared", "-o", str(out), str(SRC)]
        ):
            return out
    print("no working compiler found (tried cc, gcc, clang)", file=sys.stderr)
    return None


def main():
    out = build()
    if out and out.is_file():
        print(f"built {out}")
        return 0
    print("build failed; the pure-Python path will be used instead", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
