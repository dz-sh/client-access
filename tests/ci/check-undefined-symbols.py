#!/usr/bin/env python3
import pathlib
import subprocess
import sys


def main() -> int:
    if len(sys.argv) < 3:
        raise SystemExit("usage: check-undefined-symbols.py BINARY SYMBOL...")

    binary = pathlib.Path(sys.argv[1])
    forbidden = set(sys.argv[2:])
    result = subprocess.run(
        ["nm", "-u", str(binary)],
        check=True,
        capture_output=True,
        text=True,
    )
    symbols = {
        line.split()[-1].split("@", 1)[0]
        for line in result.stdout.splitlines()
        if line.split()
    }
    found = sorted(symbols & forbidden)
    if found:
        print(f"forbidden undefined symbols in {binary}: {', '.join(found)}", file=sys.stderr)
        return 1

    print(f"compiled-symbol boundary passed: {binary}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
