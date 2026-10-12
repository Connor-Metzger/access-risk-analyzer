"""Input validation (security requirement 5).

Every check collects errors instead of stopping at the first one, so the
person fixing the export sees every problem at once. If anything fails,
the run stops with ValidationError before any analysis happens.
"""
from __future__ import annotations

import re
from pathlib import Path

import pandas as pd

from config import ALL_ENTITLEMENTS, APPLICATIONS, AS_OF_DATE

EMPLOYEE_ID_RE = re.compile(r"^E\d{5}$")
MAX_FILE_BYTES = 20 * 1024 * 1024  # refuse anything unexpectedly huge

SCHEMAS = {
    "hr_roster.csv": [
        "employee_id", "name", "job_title", "department", "manager_id",
        "store_location", "status", "termination_date",
    ],
    "app_accounts.csv": [
        "username", "employee_id", "application", "entitlement", "last_login_date",
    ],
    "sod_rules.csv": [
        "rule_id", "entitlement_a", "entitlement_b", "risk_description", "severity",
    ],
}


class ValidationError(Exception):
    """Raised when an input file fails validation."""


def _load(path: Path, schema: str, errors: list[str]) -> pd.DataFrame | None:
    """Load a CSV and check it against SCHEMAS[schema], whatever the file is named."""
    name = path.name
    if not path.exists():
        errors.append(f"{name}: file not found at {path}")
        return None
    if path.stat().st_size > MAX_FILE_BYTES:
        errors.append(f"{name}: file is larger than {MAX_FILE_BYTES} bytes")
        return None
    try:
        # Read everything as text; we check types explicitly below.
        df = pd.read_csv(path, dtype=str, keep_default_na=False, encoding="utf-8")
    except (UnicodeDecodeError, pd.errors.ParserError) as exc:
        errors.append(f"{name}: could not be parsed as UTF-8 CSV ({exc.__class__.__name__})")
        return None

    expected = SCHEMAS[schema]
    actual = list(df.columns)
    missing = [c for c in expected if c not in actual]
    extra = [c for c in actual if c not in expected]
    if missing:
        errors.append(f"{name}: missing required column(s): {', '.join(missing)}")
    if extra:
        errors.append(f"{name}: unexpected column(s): {', '.join(extra)}")
    if missing or extra:
        return None
    if df.empty:
        errors.append(f"{name}: file has no data rows")
        return None
    return df.apply(lambda s: s.str.strip())


def _bad_dates(series: pd.Series, allow_blank: bool) -> pd.Series:
    """Boolean mask of values that aren't valid YYYY-MM-DD dates."""
    blank = series == ""
    parsed = pd.to_datetime(series.where(~blank), format="%Y-%m-%d", errors="coerce")
    bad = parsed.isna() & ~blank
    if not allow_blank:
        bad |= blank
    return bad


def _rows(mask: pd.Series, limit: int = 5) -> str:
    """Human-friendly list of 1-based CSV line numbers (header is line 1)."""
    lines = [str(i + 2) for i in mask[mask].index[:limit]]
    more = mask.sum() - len(lines)
    return ", ".join(lines) + (f" (+{more} more)" if more > 0 else "")


def validate_hr(df: pd.DataFrame, errors: list[str]) -> None:
    f = "hr_roster.csv"
    dup = df["employee_id"].duplicated(keep=False)
    if dup.any():
        errors.append(f"{f}: duplicate employee_id on line(s) {_rows(dup)}")
    bad_id = ~df["employee_id"].str.match(EMPLOYEE_ID_RE)
    if bad_id.any():
        errors.append(f"{f}: employee_id not in format E##### on line(s) {_rows(bad_id)}")
    for col in ("name", "job_title", "department", "store_location"):
        blank = df[col] == ""
        if blank.any():
            errors.append(f"{f}: blank {col} on line(s) {_rows(blank)}")
    bad_status = ~df["status"].isin(["active", "terminated"])
    if bad_status.any():
        errors.append(f"{f}: status must be 'active' or 'terminated' on line(s) {_rows(bad_status)}")

    bad_dates = _bad_dates(df["termination_date"], allow_blank=True)
    if bad_dates.any():
        errors.append(f"{f}: termination_date not YYYY-MM-DD on line(s) {_rows(bad_dates)}")
    term_no_date = (df["status"] == "terminated") & (df["termination_date"] == "")
    if term_no_date.any():
        errors.append(f"{f}: terminated employee without termination_date on line(s) {_rows(term_no_date)}")
    active_with_date = (df["status"] == "active") & (df["termination_date"] != "")
    if active_with_date.any():
        errors.append(f"{f}: active employee with a termination_date on line(s) {_rows(active_with_date)}")

    ids = set(df["employee_id"])
    has_mgr = df["manager_id"] != ""
    unknown_mgr = has_mgr & ~df["manager_id"].isin(ids)
    if unknown_mgr.any():
        errors.append(f"{f}: manager_id not found in roster on line(s) {_rows(unknown_mgr)}")
    self_mgr = df["manager_id"] == df["employee_id"]
    if self_mgr.any():
        errors.append(f"{f}: employee is their own manager on line(s) {_rows(self_mgr)}")
    if (~has_mgr).sum() != 1:
        errors.append(f"{f}: expected exactly one top-level employee with blank manager_id, "
                      f"found {(~has_mgr).sum()}")


def validate_accounts(df: pd.DataFrame, errors: list[str]) -> None:
    f = "app_accounts.csv"
    key = ["username", "application", "entitlement"]
    dup = df.duplicated(subset=key, keep=False)
    if dup.any():
        errors.append(f"{f}: duplicate (username, application, entitlement) on line(s) {_rows(dup)}")
    blank_user = df["username"] == ""
    if blank_user.any():
        errors.append(f"{f}: blank username on line(s) {_rows(blank_user)}")
    # employee_id may be blank (that's an orphan), but if present must be well-formed.
    bad_id = (df["employee_id"] != "") & ~df["employee_id"].str.match(EMPLOYEE_ID_RE)
    if bad_id.any():
        errors.append(f"{f}: employee_id not in format E##### on line(s) {_rows(bad_id)}")
    bad_app = ~df["application"].isin(APPLICATIONS.keys())
    if bad_app.any():
        errors.append(f"{f}: unknown application on line(s) {_rows(bad_app)}")
    bad_ent = ~df["entitlement"].isin(ALL_ENTITLEMENTS)
    if bad_ent.any():
        errors.append(f"{f}: unknown entitlement on line(s) {_rows(bad_ent)}")
    prefix = df["application"].map(APPLICATIONS).fillna("") + ":"
    mismatch = ~bad_app & ~bad_ent & ~pd.Series(
        [e.startswith(p) for e, p in zip(df["entitlement"], prefix)], index=df.index)
    if mismatch.any():
        errors.append(f"{f}: entitlement doesn't belong to its application on line(s) {_rows(mismatch)}")
    bad_dates = _bad_dates(df["last_login_date"], allow_blank=False)
    if bad_dates.any():
        errors.append(f"{f}: last_login_date not YYYY-MM-DD on line(s) {_rows(bad_dates)}")
    # One username must always map to the same employee within an application.
    owners = df.groupby(["application", "username"])["employee_id"].nunique()
    if (owners > 1).any():
        errors.append(f"{f}: {int((owners > 1).sum())} username(s) map to more than one employee_id")
    # A login can't happen after the date the data was exported.
    login = pd.to_datetime(df["last_login_date"], format="%Y-%m-%d", errors="coerce")
    future = login > pd.Timestamp(AS_OF_DATE)
    if future.any():
        errors.append(f"{f}: last_login_date is after the as-of date ({AS_OF_DATE}) on line(s) {_rows(future)}")

def validate_sod(df: pd.DataFrame, errors: list[str]) -> None:
    f = "sod_rules.csv"
    dup = df["rule_id"].duplicated(keep=False)
    if dup.any():
        errors.append(f"{f}: duplicate rule_id on line(s) {_rows(dup)}")
    for col in ("entitlement_a", "entitlement_b"):
        bad = ~df[col].isin(ALL_ENTITLEMENTS)
        if bad.any():
            errors.append(f"{f}: unknown {col} on line(s) {_rows(bad)}")
    same = df["entitlement_a"] == df["entitlement_b"]
    if same.any():
        errors.append(f"{f}: rule pairs an entitlement with itself on line(s) {_rows(same)}")
    bad_sev = ~df["severity"].isin(["High", "Medium", "Low"])
    if bad_sev.any():
        errors.append(f"{f}: severity must be High/Medium/Low on line(s) {_rows(bad_sev)}")


def load_and_validate(hr_path: Path, accounts_path: Path, sod_path: Path):
    """Load all three inputs, validate them, and return the DataFrames.

    Raises ValidationError listing every problem found.
    """
    errors: list[str] = []
    hr = _load(hr_path, "hr_roster.csv", errors)
    accounts = _load(accounts_path, "app_accounts.csv", errors)
    sod = _load(sod_path, "sod_rules.csv", errors)
    if hr is not None:
        validate_hr(hr, errors)
    if accounts is not None:
        validate_accounts(accounts, errors)
    if sod is not None:
        validate_sod(sod, errors)
    if errors:
        raise ValidationError("Input validation failed:\n  - " + "\n  - ".join(errors))
    return hr, accounts, sod
