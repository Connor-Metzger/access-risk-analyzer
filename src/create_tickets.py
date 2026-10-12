"""Create Jira remediation tickets for every "Revoke" decision.

Reads output/revocations.csv (written by process_decisions.py). Each ticket
contains the employee ID, application, entitlement, control reference, and
severity. Never names or usernames.

Safety features:
  - Dry run by default. Pass --live to actually call Jira.
  - Credentials come only from .env (python-dotenv); nothing is hard-coded,
    and the token is never printed or logged.
  - HTTPS required (plain http allowed only for a localhost test server).
  - Idempotent: each ticket carries a label derived from the row_id, and
    the script checks Jira for that label before creating, so reruns don't
    duplicate tickets.

Usage:
  python src/create_tickets.py            # dry run: prints what it would do
  python src/create_tickets.py --live     # creates tickets
"""
from __future__ import annotations

import argparse
import os
import sys
import time
from datetime import datetime, timezone
from urllib.parse import urlparse

import pandas as pd
import requests
from dotenv import load_dotenv

import config as C
from common import audit, read_banner_csv, sha256_file

TIMEOUT = 15
REQUIRED_ENV = ["JIRA_BASE_URL", "JIRA_EMAIL", "JIRA_API_TOKEN", "JIRA_PROJECT_KEY"]


class JiraError(Exception):
    pass


def unsanitize(value: str) -> str:
    """Undo the formula-escape apostrophe for values going to an API, not a spreadsheet."""
    if value.startswith("'") and value[1:2] in ("=", "+", "-", "@", "\t", "\r"):
        return value[1:]
    return value


def load_settings() -> dict:
    load_dotenv(C.ROOT / ".env")
    missing = [k for k in REQUIRED_ENV if not os.getenv(k)]
    if missing:
        raise JiraError(f"Missing settings in .env: {', '.join(missing)} (see .env.example)")
    base = os.environ["JIRA_BASE_URL"].rstrip("/")
    parsed = urlparse(base)
    local = parsed.hostname in ("127.0.0.1", "localhost")
    if parsed.scheme != "https" and not (parsed.scheme == "http" and local):
        raise JiraError("JIRA_BASE_URL must use https://")
    return {
        "base": base,
        "auth": (os.environ["JIRA_EMAIL"], os.environ["JIRA_API_TOKEN"]),
        "project": os.environ["JIRA_PROJECT_KEY"],
        "issue_type": os.getenv("JIRA_ISSUE_TYPE", "Task"),
    }


def dedupe_label(row_id: str) -> str:
    """Unique per campaign + row, so next quarter's revocation isn't skipped."""
    return f"arv-{C.AS_OF_DATE:%Y%m%d}-{row_id.lower()}"


def ticket_fields(row: pd.Series, project: str, issue_type: str) -> dict:
    who = row["employee_id"] or "orphaned account (no HR owner)"
    summary = f"[{row['severity']}] Revoke {row['entitlement']} - {who} - {row['application']}"
    facts = [
        ("Employee ID", row["employee_id"] or "none (orphaned account)"),
        ("Application", row["application"]),
        ("Entitlement to remove", row["entitlement"]),
        ("Control reference", row["controls"]),
        ("Severity", row["severity"]),
        ("Finding(s)", row["flags"] or "Not flagged; revoked by reviewer"),
        ("Finding ID(s)", row["finding_ids"] or "n/a"),
        ("Review row ID", row["row_id"]),
        ("Approved by reviewer ID", row["reviewer_id"]),
    ]
    items = [{"type": "listItem", "content": [{"type": "paragraph", "content": [
        {"type": "text", "text": f"{k}: ", "marks": [{"type": "strong"}]},
        {"type": "text", "text": str(v)}]}]} for k, v in facts]
    description = {"type": "doc", "version": 1, "content": [
        {"type": "paragraph", "content": [{"type": "text", "text":
            "Quarterly access review revocation. Remove the access below, then attach "
            "evidence (screenshot or system log) and close this ticket."}]},
        {"type": "bulletList", "content": items},
        {"type": "paragraph", "content": [{"type": "text", "text": C.CONFIDENTIAL,
                                           "marks": [{"type": "em"}]}]},
    ]}
    return {
        "project": {"key": project},
        "issuetype": {"name": issue_type},
        "summary": summary[:250],
        "description": description,
        "labels": ["access-review", f"severity-{row['severity'].lower()}", dedupe_label(row["row_id"])],
    }


def _request(method: str, url: str, settings: dict, **kw) -> requests.Response:
    for attempt in range(4):
        resp = requests.request(method, url, auth=settings["auth"], timeout=TIMEOUT,
                                headers={"Accept": "application/json"}, **kw)
        if resp.status_code == 429:  # rate limited: honor Retry-After
            time.sleep(min(int(resp.headers.get("Retry-After", 2 ** attempt)), 30))
            continue
        if resp.status_code in (401, 403):
            raise JiraError(f"Jira refused the credentials (HTTP {resp.status_code}). "
                            "Check JIRA_EMAIL / JIRA_API_TOKEN and project permissions.")
        return resp
    raise JiraError("Jira rate limit: gave up after retries")


def exists(settings: dict, label: str) -> str | None:
    jql = f'project = "{settings["project"]}" AND labels = "{label}"'
    resp = _request("POST", f"{settings['base']}/rest/api/3/search/jql", settings,
                    json={"jql": jql, "fields": ["key"], "maxResults": 1})
    if resp.status_code != 200:
        raise JiraError(f"Search failed (HTTP {resp.status_code})")
    issues = resp.json().get("issues", [])
    return issues[0]["key"] if issues else None


def create(settings: dict, fields: dict) -> str:
    resp = _request("POST", f"{settings['base']}/rest/api/3/issue", settings, json={"fields": fields})
    if resp.status_code != 201:
        # Jira error bodies describe field problems; they contain no secrets.
        detail = resp.json().get("errors", {}) if resp.headers.get("content-type", "").startswith(
            "application/json") else ""
        raise JiraError(f"Create failed (HTTP {resp.status_code}): {detail}")
    return resp.json()["key"]


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--live", action="store_true", help="Actually create tickets (default: dry run)")
    args = ap.parse_args()

    if not C.REVOCATIONS_CSV.exists():
        print("ERROR: output/revocations.csv not found; run process_decisions.py first", file=sys.stderr)
        return 1
    audit("create_tickets: read revocations.csv", "-", sha256_file(C.REVOCATIONS_CSV))
    rows = read_banner_csv(C.REVOCATIONS_CSV).map(unsanitize)
    print(f"{len(rows)} revocation(s) to ticket  |  mode: {'LIVE' if args.live else 'DRY RUN'}")

    settings = None
    if args.live:
        try:
            settings = load_settings()
        except JiraError as exc:
            print(f"ERROR: {exc}", file=sys.stderr)
            return 1

    ledger = []
    created = skipped = 0
    for _, row in rows.iterrows():
        fields = ticket_fields(row, settings["project"] if settings else "DRYRUN",
                               settings["issue_type"] if settings else "Task")
        label = dedupe_label(row["row_id"])
        if not args.live:
            print(f"  would create: {fields['summary']}")
            continue
        try:
            key = exists(settings, label)
            if key:
                skipped += 1
                status = "already exists"
            else:
                key = create(settings, fields)
                created += 1
                status = "created"
        except (JiraError, requests.RequestException) as exc:
            print(f"ERROR on row {row['row_id']}: {exc.__class__.__name__}: {exc}", file=sys.stderr)
            audit(f"create_tickets: FAILED for row {row['row_id']}")
            return 1
        audit(f"create_tickets: {status} {key} for employee {row['employee_id'] or 'orphan'}", 1)
        ledger.append({"row_id": row["row_id"], "issue_key": key, "status": status,
                       "utc": datetime.now(timezone.utc).isoformat(timespec="seconds")})
        print(f"  {status:<15} {key}  {fields['summary']}")

    if args.live:
        pd.DataFrame(ledger).to_csv(C.TICKET_LEDGER_CSV, index=False)
        audit("create_tickets: wrote ticket_ledger.csv", len(ledger), sha256_file(C.TICKET_LEDGER_CSV))
        print(f"\nCreated {created}, skipped {skipped} existing.")
    else:
        audit("create_tickets: dry run", len(rows))
        print("\nDry run only. Add Jira settings to .env and rerun with --live.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
