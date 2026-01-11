
# -*- coding: utf-8 -*-
"""
run.py — PostRBE launcher (pure Python, cross-terminal safe)

Put this file in the folder that contains:
  - PostRBE(base)
  - PostRBE*      (or PostRBE_star)
  - MPostRBE*     (or MPostRBE_star)

Then run:  python run.py
It will show a menu to run one of the three demos using the *current* Python interpreter.
"""
from __future__ import annotations
import sys, os, argparse, subprocess
from pathlib import Path
from typing import List, Optional

# -------- helpers --------
def find_dir(base: Path, expected: Optional[str], prefixes: List[str]) -> Optional[Path]:
    """
    Try exact name first; if not found, scan subfolders and return the first whose name startswith any prefix.
    """
    if expected:
        p = base / expected
        if p.exists() and p.is_dir():
            return p
    # fallback: scan
    for child in base.iterdir():
        if not child.is_dir():
            continue
        name_low = child.name.lower()
        for pref in prefixes:
            if name_low.startswith(pref.lower()):
                return child
    return None

def run_demo(proj_dir: Path, demo_name: str, extra_dev_flags: bool=True) -> int:
    if not proj_dir or not proj_dir.exists():
        print(f"[ERR] Project folder not found: {proj_dir}", file=sys.stderr)
        return 2
    demo = proj_dir / demo_name
    if not demo.exists():
        print(f"[ERR] Demo script not found: {demo}", file=sys.stderr)
        return 3
    # Use current interpreter; no shell; pass absolute path
    argv = [sys.executable]
    if extra_dev_flags:
        argv += ["-u", "-X", "dev", "-X", "faulthandler"]
    argv += [str(demo)]
    print(f"[RUN] {proj_dir.name} -> {demo.name}")
    print(f"[PY ] {sys.executable}")
    try:
        # Ensure working dir is the project (so relative imports work)
        return subprocess.call(argv, cwd=str(proj_dir))
    except KeyboardInterrupt:
        print("\n[INTERRUPTED]")
        return 130

# -------- main --------
def main():
    base = Path(__file__).resolve().parent

    # Resolve three projects (try exact, else by prefix)
    p_base  = find_dir(base, "PostRBE(base)", prefixes=["postrbe(base)", "postrbe_base", "postrbe"])
    # 先精确找 PostRBE_star（你已经改名了）
    p_star = base / "PostRBE_star"
    if not (p_star.exists() and p_star.is_dir()):
        p_star = None

    # 如果没找到，再扫描所有目录：必须包含 postrbe 且包含 star/∗/*，并且不能包含 base/mpost
    if p_star is None:
        for child in base.iterdir():
            if not child.is_dir():
                continue
            name = child.name.lower()
            if "postrbe" not in name:
                continue
            if "base" in name or "mpost" in name:
                continue
            if ("star" in name) or ("∗" in child.name) or ("*" in child.name):
                p_star = child
                break

    p_multi = find_dir(base, "MPostRBE\u2217".encode('utf-8').decode('unicode_escape'), prefixes=["mpostrbe", "mpostrbe_","mpostrbe-","mpostrbe "] )
    # Small disambiguation: prefer names that contain "star" for p_star, and "multi"/"mpost" for p_multi
    for p in [p_star, p_multi]:
        # nothing fancy; finder already returned the first match
        pass

    parser = argparse.ArgumentParser(description="PostRBE launcher (base / star / multi)")
    parser.add_argument("--project", "-p", choices=["1","2","3","base","star","multi"], help="project to run")
    parser.add_argument("--no-dev-flags", action="store_true", help="do not pass -u -X dev -X faulthandler")
    parser.add_argument("--list", action="store_true", help="list discovered projects and exit")
    args = parser.parse_args()

    items = [
        ("1","PostRBE (base)",  p_base,  "demo_postrbe.py"),
        ("2","PostRBE* (star)", p_star,  "demo_postrbe_star.py"),
        ("3","MPostRBE* (multi)", p_multi, "demo_mpostrbe_star.py"),
    ]

    if args.list:
        print("Discovered projects under:", base)
        for key, name, p, demo in items:
            status = "OK" if (p and (p/demo).exists()) else "MISSING"
            path = str(p) if p else "(not found)"
            print(f" {key}. {name:<22} -> {path}")
        return 0

    # If project specified via CLI
    if args.project:
        mapping = {"1":"base","2":"star","3":"multi"}
        sel = mapping.get(args.project, args.project)
        for key, name, p, demo in items:
            if sel in (key, name.split()[0].lower(), name.split()[0].lower().rstrip('*'), name.split()[0].lower().replace('*','')):
                return run_demo(p, demo, extra_dev_flags=(not args.no_dev_flags))

    # Interactive menu
    while True:
        print("="*56)
        print(" PostRBE Launcher (Python)")
        print("="*56)
        for key, name, p, demo in items:
            ok = p and (p / demo).exists()
            mark = "[OK]" if ok else "[!!]"
            print(f" {key}. {name:<22} {mark}  {p if p else ''}")
        print(" 0. Exit")
        sel = input("Choose project to run [0-3]: ").strip()
        if sel in ("0","q","quit","exit",""):
            return 0
        if sel not in ("1","2","3"):
            continue
        idx = int(sel)-1
        key, name, p, demo = items[idx]
        rc = run_demo(p, demo, extra_dev_flags=(not args.no_dev_flags))
        print(f"[EXIT CODE] {rc}")
        input("Press Enter to return to menu...")

if __name__ == "__main__":
    raise SystemExit(main())
