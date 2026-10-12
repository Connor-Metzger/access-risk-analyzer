"""Data retention cleanup (security requirement 13).

Deletes generated reports and packets older than the retention period
(default 90 days, from config.RETENTION_DAYS). The audit log is NOT deleted
here: it is audit evidence with a longer retention (see README).

Before each deletion the file's SHA-256 is written to the audit log, so there
is a record of what existed and when it was destroyed.

Usage:
  python src/cleanup.py              # delete files older than 90 days
  python src/cleanup.py --dry-run    # show what would be deleted
  python src/cleanup.py --all        # delete everything now (end of campaign)
"""
from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path

import config as C
from common import audit, sha256_file

TARGETS = [C.OUTPUT_DIR, C.PACKETS_DIR]


def candidates(older_than_days: int | None) -> list[Path]:
    cutoff = time.time() - older_than_days * 86400 if older_than_days is not None else None
    found = []
    for root in TARGETS:
        if not root.exists():
            continue
        root = root.resolve()
        for p in root.rglob("*"):
            # Never follow symlinks out of the target folders.
            if p.is_symlink() or not p.is_file():
                continue
            if root not in p.resolve().parents:
                continue
            if p.name == ".gitkeep":
                continue
            if cutoff is None or p.stat().st_mtime < cutoff:
                found.append(p)
    return sorted(found)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--all", action="store_true", help="Delete all generated files regardless of age")
    ap.add_argument("--dry-run", action="store_true", help="List files without deleting")
    ap.add_argument("--days", type=int, default=C.RETENTION_DAYS, help="Retention period in days")
    args = ap.parse_args()

    files = candidates(None if args.all else args.days)
    scope = "all generated files" if args.all else f"files older than {args.days} days"
    print(f"{len(files)} {scope} in output/ and packets/")
    for p in files:
        rel = p.relative_to(C.ROOT)
        if args.dry_run:
            print(f"  would delete {rel}")
            continue
        digest = sha256_file(p)
        p.unlink()
        audit(f"cleanup: deleted {rel}", "-", digest)
        print(f"  deleted {rel}")
    # Remove empty subfolders (e.g. packets/completed) but keep the top-level dirs.
    if not args.dry_run:
        for root in TARGETS:
            for d in sorted((x for x in root.rglob("*") if x.is_dir()), reverse=True):
                if not any(d.iterdir()):
                    d.rmdir()
    audit(f"cleanup: run complete ({'dry run' if args.dry_run else 'deleted'})", len(files))
    return 0


if __name__ == "__main__":
    sys.exit(main())
