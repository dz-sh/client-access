#!/usr/bin/env python3
import pathlib
import sys


def matching(root: pathlib.Path, pattern: str):
    return sorted(path for path in root.rglob(pattern) if path.is_file())


def main() -> int:
    if len(sys.argv) != 2:
        raise SystemExit("usage: check-sdk-isolation.py ARTIFACT_DIRECTORY")

    root = pathlib.Path(sys.argv[1])
    required = ["client-access-core_*.ipk", "luci-app-client-access_*.ipk"]
    forbidden = ["client-access-bpf_*.ipk", "client-access-sfo_*.ipk"]
    errors = []

    for pattern in required:
        if not matching(root, pattern):
            errors.append(f"required package missing: {pattern}")
    for pattern in forbidden:
        paths = matching(root, pattern)
        if paths:
            errors.append(f"unexpected optional package: {paths[0]}")

    if errors:
        for error in errors:
            print(f"SDK isolation failed: {error}", file=sys.stderr)
        return 1

    (root / "v45-build-isolation.txt").write_text(
        "Core and LuCI built without selecting the BPF or SFO package.\n",
        encoding="utf-8",
    )
    print("OpenWrt core/LuCI package isolation passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
