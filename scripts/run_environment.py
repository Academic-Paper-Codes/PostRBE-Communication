#!/usr/bin/env python3
"""Check the local evaluator environment without modifying source data."""
from __future__ import annotations

import argparse
import os
import platform
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", type=Path, default=Path(tempfile.gettempdir()) / "postrbe-environment-check")
    args = parser.parse_args()
    failures = []
    print(f"python={sys.version.split()[0]}")
    print(f"platform={platform.platform()}")
    print(f"cpu_count={os.cpu_count()}")
    for module in ("numpy", "cryptography"):
        try:
            imported = __import__(module)
            print(f"{module}={getattr(imported, '__version__', 'installed')}")
        except ImportError:
            failures.append(f"missing dependency: {module}")
    try:
        args.out.mkdir(parents=True, exist_ok=True)
        marker = args.out / ".write-check"
        marker.write_text("ok", encoding="ascii")
        marker.unlink()
        print(f"output_writable={args.out.resolve()}")
    except OSError as exc:
        failures.append(f"output is not writable: {exc}")
    if failures:
        for failure in failures:
            print(f"FAIL {failure}", file=sys.stderr)
        return 1
    print("ENVIRONMENT PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
