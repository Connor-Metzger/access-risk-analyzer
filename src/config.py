"""Central configuration for the Access Risk Analyzer.

Everything that affects results lives here so a run is fully reproducible:
the random seed, the "as-of" date used for dormancy math, and the review deadline.
"""
from __future__ import annotations

from datetime import date, timedelta
from pathlib import Path

# ---------------------------------------------------------------------------
# Paths (all relative to the repo root, never hard-coded absolute paths)
# ---------------------------------------------------------------------------
ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = ROOT / "data"
OUTPUT_DIR = ROOT / "output"
PACKETS_DIR = ROOT / "packets"
COMPLETED_DIR = PACKETS_DIR / "completed"
LOG_DIR = ROOT / "logs"
DOCS_DIR = ROOT / "docs"

HR_FILE = DATA_DIR / "hr_roster.csv"
ACCOUNTS_FILE = DATA_DIR / "app_accounts.csv"
SOD_FILE = DATA_DIR / "sod_rules.csv"
ANSWER_KEY_FILE = DATA_DIR / "planted_issues.csv"

FINDINGS_XLSX = OUTPUT_DIR / "findings_report.xlsx"
FINDINGS_CSV = OUTPUT_DIR / "findings.csv"
PACKET_MANIFEST = PACKETS_DIR / "manifest.json"
CAMPAIGN_XLSX = OUTPUT_DIR / "campaign_summary.xlsx"
CAMPAIGN_ROWS_CSV = OUTPUT_DIR / "campaign_decisions.csv"
REVOCATIONS_CSV = OUTPUT_DIR / "revocations.csv"
TICKET_LEDGER_CSV = OUTPUT_DIR / "ticket_ledger.csv"
AUDIT_LOG = LOG_DIR / "audit.log"

# ---------------------------------------------------------------------------
# Reproducibility
# ---------------------------------------------------------------------------
SEED = 20260930
# Fixed "as-of" date for the review. Dormancy is measured against this date,
# NOT date.today(), so rerunning next month gives identical results.
AS_OF_DATE = date(2026, 9, 30)
REVIEW_DEADLINE = AS_OF_DATE + timedelta(days=14)
DORMANCY_DAYS = 90
RETENTION_DAYS = 90

CONFIDENTIAL = "Confidential - Internal Use Only"
COMPANY = "Keystone Fuel & Market (fictional)"

# ---------------------------------------------------------------------------
# Applications and entitlements
# ---------------------------------------------------------------------------
APPLICATIONS = {
    "POS": "POS",
    "Payroll": "Payroll",
    "Accounts Payable": "AP",
}

ENTITLEMENTS = {
    "POS": [
        "POS: Cashier",
        "POS: Void Transaction",
        "POS: Issue Refund",
        "POS: Price Override",
        "POS: Approve Cash Reconciliation",
        "POS: Store Manager Admin",
    ],
    "Payroll": [
        "Payroll: View Employee",
        "Payroll: Enter Timecards",
        "Payroll: Add Employee",
        "Payroll: Edit Pay Rate",
        "Payroll: Run Payroll",
        "Payroll: Approve Payroll",
    ],
    "Accounts Payable": [
        "AP: View Invoices",
        "AP: Enter Invoice",
        "AP: Create Vendor",
        "AP: Approve Payment",
    ],
}
ALL_ENTITLEMENTS = {e for ents in ENTITLEMENTS.values() for e in ents}

# Entitlements that only store managers (or above) should hold.
MANAGER_LEVEL_ENTITLEMENTS = {
    "POS: Approve Cash Reconciliation",
    "POS: Store Manager Admin",
    "POS: Price Override",
    "Payroll: Approve Payroll",
    "Payroll: Edit Pay Rate",
}
# Job titles that must never hold manager-level entitlements.
FRONTLINE_TITLES = {"Store Associate", "Cashier"}

FINANCIAL_APPS = {"Payroll", "Accounts Payable"}

# ---------------------------------------------------------------------------
# Finding types -> control mapping
# ---------------------------------------------------------------------------
TERMINATED = "Terminated User - Active Access"
DORMANT = "Inactive Account (90+ days)"
EXCESS = "Excess Privilege"
SOD = "Separation of Duties Violation"
ORPHAN = "Orphaned Account"

FINDING_TYPES = [TERMINATED, DORMANT, EXCESS, SOD, ORPHAN]

CONTROLS = {
    TERMINATED: ("PCI-DSS v4.0 8.2.5",
                 "Access for terminated users is immediately revoked."),
    DORMANT: ("PCI-DSS v4.0 8.2.6",
              "Inactive user accounts are removed or disabled within 90 days."),
    EXCESS: ("NIST 800-53 AC-6",
             "Least Privilege: users hold only the access their role requires."),
    SOD: ("NIST 800-53 AC-5",
          "Separation of Duties: conflicting duties are split across people."),
    ORPHAN: ("NIST 800-53 AC-2",
             "Account Management: every account has an accountable owner."),
}

SEVERITY_ORDER = {"High": 0, "Medium": 1, "Low": 2}
