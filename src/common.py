"""Shared security helpers used by every script.

- sha256_file:       integrity hashing of inputs and outputs (requirement 8)
- audit:             safe audit logging, IDs and counts only (requirement 7)
- sanitize_*:        CSV/Excel formula-injection protection (requirement 6)
- account_ref:       a stable, non-identifying reference for an account
"""
from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from pathlib import Path

import pandas as pd

from config import AUDIT_LOG, LOG_DIR

# Characters that make a spreadsheet treat a cell as a formula (OWASP list).
DANGEROUS_PREFIXES = ("=", "+", "-", "@", "\t", "\r")


# ---------------------------------------------------------------------------
# Integrity
# ---------------------------------------------------------------------------
def sha256_file(path: Path) -> str:
    """Return the SHA-256 hex digest of a file, streamed in chunks."""
    digest = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def account_ref(username: str, application: str) -> str:
    """Stable account reference that doesn't expose the username.

    Usernames are often built from people's names (e.g. jsmith), so tickets,
    logs, and dashboards use this hashed reference instead.
    """
    raw = f"{application}|{username}".encode("utf-8")
    return "ACCT-" + hashlib.sha256(raw).hexdigest()[:10].upper()


# ---------------------------------------------------------------------------
# Audit logging
# ---------------------------------------------------------------------------
def audit(action: str, record_count: int | str = "-", file_hash: str = "-") -> None:
    """Append one line to logs/audit.log.

    Format: ISO-8601 UTC timestamp | action | record_count | file_hash
    Callers must pass only identifiers and counts. Never names or full rows.
    """
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    ts = datetime.now(timezone.utc).isoformat(timespec="seconds")
    # Strip separators/newlines so a crafted value can't forge log lines.
    safe_action = str(action).replace("|", "/").replace("\n", " ").replace("\r", " ")
    line = f"{ts} | {safe_action} | {record_count} | {file_hash}\n"
    with open(AUDIT_LOG, "a", encoding="utf-8") as fh:
        fh.write(line)


# ---------------------------------------------------------------------------
# Formula-injection protection
# ---------------------------------------------------------------------------
def sanitize_value(value):
    """Prefix an apostrophe to strings that a spreadsheet could execute.

    Only strings are touched, so real numbers (including negatives) and dates
    keep their types.
    """
    if isinstance(value, str) and value.startswith(DANGEROUS_PREFIXES):
        return "'" + value
    return value


def sanitize_df(df: pd.DataFrame) -> pd.DataFrame:
    """Return a copy of df with every string cell (and header) sanitized."""
    out = df.copy()
    for col in out.columns:
        if out[col].dtype == object or pd.api.types.is_string_dtype(out[col]):
            out[col] = out[col].map(sanitize_value)
    out.columns = [sanitize_value(c) for c in out.columns]
    return out


def write_sanitized_csv(df: pd.DataFrame, path: Path, action: str) -> str:
    """Sanitize, write a CSV with a confidentiality banner, hash it, log it."""
    path.parent.mkdir(parents=True, exist_ok=True)
    from config import CONFIDENTIAL  # local import avoids a cycle at load time

    with open(path, "w", encoding="utf-8", newline="") as fh:
        fh.write(f"# {CONFIDENTIAL}\n")
        sanitize_df(df).to_csv(fh, index=False)
    digest = sha256_file(path)
    audit(action, len(df), digest)
    return digest


def read_banner_csv(path: Path) -> pd.DataFrame:
    """Read a CSV written by write_sanitized_csv (skips the banner line)."""
    return pd.read_csv(path, comment=None, skiprows=1, dtype=str, keep_default_na=False)
