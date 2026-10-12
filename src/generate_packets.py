"""Generate one certification packet (Excel) per reviewing manager.

Each packet lists ONLY the reviewer's direct reports and their access
(security requirement 9). If a manager has been terminated, their team is
escalated to the next active manager up the chain. Orphaned accounts have no
manager, so they go to a separate IAM / application-owner packet.

Usage:  python src/generate_packets.py
"""
from __future__ import annotations

import hashlib
import json
import sys
from datetime import datetime, timezone

import pandas as pd
from openpyxl import Workbook
from openpyxl.styles import Alignment, Border, Font, PatternFill, Protection, Side
from openpyxl.utils import get_column_letter
from openpyxl.worksheet.datavalidation import DataValidation

import config as C
from analyzer import run_analysis
from common import audit, sanitize_value, sha256_file
from validation import ValidationError

FONT = "Arial"
RED = PatternFill("solid", start_color="F4B6B6")
YELLOW = PatternFill("solid", start_color="FFF2A8")
INPUT_FILL = PatternFill("solid", start_color="DDEBF7")
HDR_FILL = PatternFill("solid", start_color="1F3864")
GREY = Font(name=FONT, italic=True, color="7F7F7F", size=9)
THIN = Border(bottom=Side(style="thin", color="BFBFBF"))

ORPHAN_REVIEWER = "IAM-ORPHANS"
TABLE_HEADER_ROW = 14
COLUMNS = ["row_id", "employee_id", "name", "job_title", "store_location", "employee_status",
           "application", "entitlement", "last_login_date", "flags", "severity", "controls",
           "finding_ids", "Decision", "Justification"]
WIDTHS = {"row_id": 15, "employee_id": 11, "name": 20, "job_title": 22, "store_location": 13,
          "employee_status": 12, "application": 16, "entitlement": 32, "last_login_date": 13,
          "flags": 38, "severity": 9, "controls": 24, "finding_ids": 14, "Decision": 11,
          "Justification": 45}


def row_id(employee_or_user: str, application: str, entitlement: str) -> str:
    raw = f"{employee_or_user}|{application}|{entitlement}".encode()
    return "R-" + hashlib.sha256(raw).hexdigest()[:10].upper()


def resolve_reviewers(hr: pd.DataFrame) -> dict[str, tuple[str, bool]]:
    """Map employee_id -> (reviewer_id, escalated?).

    Walk up the chain past terminated managers so no team is left without a
    reviewer. A terminated person can never be a reviewer.
    """
    mgr = hr.set_index("employee_id")["manager_id"].to_dict()
    status = hr.set_index("employee_id")["status"].to_dict()
    result = {}
    for emp in hr["employee_id"]:
        reviewer, escalated, hops = mgr.get(emp, ""), False, 0
        while reviewer and status.get(reviewer) == "terminated":
            reviewer, escalated, hops = mgr.get(reviewer, ""), True, hops + 1
            if hops > 20:
                raise RuntimeError(f"Manager chain loop detected for {emp}")
        if reviewer:
            result[emp] = (reviewer, escalated)
    return result


def build_rows(accts: pd.DataFrame, accounts: pd.DataFrame, findings: pd.DataFrame,
               sod: pd.DataFrame, hr: pd.DataFrame) -> pd.DataFrame:
    """One row per entitlement, with any findings that touch it attached."""
    rows = accts.merge(accounts[["application", "username", "has_hr_record", "name", "job_title",
                                 "store_location", "status"]],
                       on=["application", "username"], how="left")
    rows = rows.rename(columns={"status": "employee_status"})
    owner = rows["employee_id"].where(rows["has_hr_record"], "ORPHAN:" + rows["username"])
    rows["row_id"] = [row_id(o, a, e) for o, a, e in zip(owner, rows["application"], rows["entitlement"])]

    sod_pairs = sod.set_index("rule_id")[["entitlement_a", "entitlement_b"]].to_dict("index")
    flags: dict[str, list[tuple[str, str, str, str]]] = {r: [] for r in rows["row_id"]}
    for _, f in findings.iterrows():
        apps = f["application"].split(" + ")
        target = rows[(rows["username"] == f["username"]) & rows["application"].isin(apps)]
        if f["issue_type"] == C.EXCESS:
            target = target[target["entitlement"] == f["detail"]]
        elif f["issue_type"] == C.SOD:
            pair = sod_pairs[f["detail"]]
            target = target[target["entitlement"].isin([pair["entitlement_a"], pair["entitlement_b"]])]
        label = f["issue_type"] + (f" ({f['detail']})" if f["issue_type"] == C.SOD else "")
        for rid in target["row_id"]:
            flags[rid].append((label, f["severity"], f["control_id"], f["finding_id"]))

    def agg(rid, i):
        vals = [x[i] for x in flags[rid]]
        return "; ".join(dict.fromkeys(vals))

    rows["flags"] = [agg(r, 0) for r in rows["row_id"]]
    rows["severity"] = [min((x[1] for x in flags[r]), key=C.SEVERITY_ORDER.get, default="")
                        for r in rows["row_id"]]
    rows["controls"] = [agg(r, 2) for r in rows["row_id"]]
    rows["finding_ids"] = [agg(r, 3) for r in rows["row_id"]]
    rows["Decision"] = ""
    rows["Justification"] = ""

    reviewers = resolve_reviewers(hr)
    rows["reviewer_id"] = [reviewers.get(e, ("", False))[0] if h else ORPHAN_REVIEWER
                           for e, h in zip(rows["employee_id"], rows["has_hr_record"])]
    rows["escalated"] = [reviewers.get(e, ("", False))[1] if h else False
                         for e, h in zip(rows["employee_id"], rows["has_hr_record"])]
    # Orphans have no person behind them; show the username so owners can find it.
    rows.loc[~rows["has_hr_record"], "name"] = "(no HR record) " + rows["username"]
    rows.loc[~rows["has_hr_record"], "employee_status"] = "no HR record"
    for col in ("name", "job_title", "store_location", "employee_status"):
        rows[col] = rows[col].fillna("")
    rows["sev_rank"] = rows["severity"].map(C.SEVERITY_ORDER).fillna(9)
    rows = rows.sort_values(["sev_rank", "name", "application", "entitlement"]).drop(columns="sev_rank")
    return rows


def write_packet(path, reviewer_id: str, reviewer_label: str, rows: pd.DataFrame,
                 escalated_from: list[str]) -> None:
    wb = Workbook()
    ws = wb.active
    ws.title = "Access Review"
    ws.sheet_properties.tabColor = "1F3864"

    ws["A1"] = C.CONFIDENTIAL.upper()
    ws["A1"].font = Font(name=FONT, bold=True, color="C00000", size=11)
    ws["A2"] = "Quarterly Access Certification"
    ws["A2"].font = Font(name=FONT, bold=True, size=14)
    info = [
        ("Reviewer", sanitize_value(reviewer_label)),
        ("Review deadline", C.REVIEW_DEADLINE.isoformat()),
        ("Rows to review", len(rows)),
        ("Flagged rows", int((rows["flags"] != "").sum())),
    ]
    for i, (k, v) in enumerate(info, 3):
        ws.merge_cells(start_row=i, start_column=1, end_row=i, end_column=2)
        ws.cell(row=i, column=1, value=k).font = Font(name=FONT, bold=True)
        c = ws.cell(row=i, column=3, value=v)
        c.font = Font(name=FONT)
        c.alignment = Alignment(horizontal="left")
    if escalated_from:
        ws.cell(row=7, column=1, value=("Includes team(s) escalated from terminated manager(s): "
                                        + ", ".join(escalated_from))).font = Font(name=FONT, bold=True,
                                                                                  color="C00000")
    ws["A8"] = ("Instructions: for EVERY row choose Keep or Revoke in the Decision column. "
                "A Justification is required for any flagged row you Keep. Only the blue cells "
                "are editable. See docs/manager_job_aid.pdf.")
    ws["A8"].font = Font(name=FONT, size=10)
    ws["A9"] = "Legend: red = High risk, yellow = Medium risk, no color = Low or not flagged."
    ws["A9"].font = Font(name=FONT, size=10)
    ws["A10"] = ("Example (format only, not a real row): Decision = Keep | Justification = "
                 "'Covers night shift as acting lead through 2026-11-30; HR ticket HR-1042'")
    ws["A10"].font = GREY

    ws["A11"] = "Attestation (your name)"
    ws["A12"] = "Date submitted (YYYY-MM-DD)"
    box = Side(style="thin")
    for r in (11, 12):
        ws.merge_cells(start_row=r, start_column=1, end_row=r, end_column=2)
        ws.cell(row=r, column=1).font = Font(name=FONT, bold=True, size=9)
        ws.merge_cells(start_row=r, start_column=3, end_row=r, end_column=4)
        for col in (3, 4):
            cell = ws.cell(row=r, column=col)
            cell.fill = INPUT_FILL
            cell.protection = Protection(locked=False)
            cell.border = Border(left=box, right=box, top=box, bottom=box)

    hr_ = TABLE_HEADER_ROW
    for j, col in enumerate(COLUMNS, 1):
        c = ws.cell(row=hr_, column=j, value=col)
        c.font = Font(name=FONT, bold=True, color="FFFFFF")
        c.fill = HDR_FILL
        c.alignment = Alignment(wrap_text=True, vertical="center")
        ws.column_dimensions[get_column_letter(j)].width = WIDTHS[col]

    dec_col = COLUMNS.index("Decision") + 1
    just_col = COLUMNS.index("Justification") + 1
    for i, r in enumerate(rows[COLUMNS].itertuples(index=False), hr_ + 1):
        fill = RED if r.severity == "High" else YELLOW if r.severity == "Medium" else None
        for j, val in enumerate(r, 1):
            c = ws.cell(row=i, column=j, value=sanitize_value(val))
            c.font = Font(name=FONT, size=10)
            c.border = THIN
            if fill:
                c.fill = fill
        for j in (dec_col, just_col):
            c = ws.cell(row=i, column=j)
            c.protection = Protection(locked=False)
            if not fill:
                c.fill = INPUT_FILL

    last = hr_ + len(rows)
    dv = DataValidation(type="list", formula1='"Keep,Revoke"', allow_blank=True,
                        showErrorMessage=True, errorTitle="Invalid decision",
                        error="Choose Keep or Revoke from the list.")
    dv.add(f"{get_column_letter(dec_col)}{hr_ + 1}:{get_column_letter(dec_col)}{max(last, hr_ + 1)}")
    ws.add_data_validation(dv)
    ws.freeze_panes = ws.cell(row=hr_ + 1, column=3)
    ws.auto_filter.ref = f"A{hr_}:{get_column_letter(len(COLUMNS))}{max(last, hr_ + 1)}"

    # Lock everything except the input cells. This prevents accidental edits
    # to the evidence; it's an integrity aid, not a security boundary.
    ws.protection.sheet = True
    ws.protection.autoFilter = False
    ws.protection.sort = False
    ws.oddHeader.center.text = C.CONFIDENTIAL
    ws.oddFooter.center.text = f"Packet {reviewer_id} | Page &P of &N"
    ws.page_setup.orientation = "landscape"
    ws.page_setup.fitToWidth = 1
    ws.sheet_properties.pageSetUpPr.fitToPage = True
    ws.page_setup.fitToHeight = 0

    meta = wb.create_sheet("_meta")
    for i, (k, v) in enumerate([("packet_id", f"PKT-{reviewer_id}"), ("reviewer_id", reviewer_id),
                                ("generated_utc", datetime.now(timezone.utc).isoformat(timespec="seconds")),
                                ("review_deadline", C.REVIEW_DEADLINE.isoformat()),
                                ("row_count", len(rows))], 1):
        meta.cell(row=i, column=1, value=k)
        meta.cell(row=i, column=2, value=v)
    meta.sheet_state = "veryHidden"
    wb.save(path)


def main() -> int:
    audit("generate_packets: run started")
    try:
        hr, accts, sod, accounts, findings, warnings, hashes = run_analysis()
    except ValidationError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2

    rows = build_rows(accts, accounts, findings, sod, hr)
    names = hr.set_index("employee_id")["name"].to_dict()
    mgr_of = hr.set_index("employee_id")["manager_id"].to_dict()

    C.PACKETS_DIR.mkdir(parents=True, exist_ok=True)
    for old in C.PACKETS_DIR.glob("packet_*.xlsx"):
        old.unlink()
    manifest = {"generated_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                "review_deadline": C.REVIEW_DEADLINE.isoformat(), "packets": []}

    for reviewer_id, grp in rows.groupby("reviewer_id"):
        # Requirement 9 self-check: every employee in this packet must be a
        # direct report of the reviewer (or escalated to them). Abort if not.
        for emp, esc in zip(grp["employee_id"], grp["escalated"]):
            if reviewer_id == ORPHAN_REVIEWER:
                continue
            direct = mgr_of.get(emp) == reviewer_id
            if not (direct or esc):
                raise RuntimeError(f"Packet {reviewer_id} would contain {emp}, who is not a direct report")

        escalated_from = sorted({mgr_of[e] for e in grp.loc[grp["escalated"], "employee_id"]})
        label = ("IAM Governance / Application Owners" if reviewer_id == ORPHAN_REVIEWER
                 else f"{names[reviewer_id]} ({reviewer_id})")
        path = C.PACKETS_DIR / f"packet_{reviewer_id}.xlsx"
        write_packet(path, reviewer_id, label, grp, escalated_from)
        digest = sha256_file(path)
        audit(f"generate_packets: wrote packet for reviewer {reviewer_id}", len(grp), digest)
        manifest["packets"].append({
            "file": path.name, "reviewer_id": reviewer_id, "row_count": len(grp),
            "flagged_rows": int((grp["flags"] != "").sum()), "sha256": digest,
            "escalated_from": escalated_from, "row_ids": sorted(grp["row_id"]),
        })

    C.PACKET_MANIFEST.write_text(json.dumps(manifest, indent=2))
    audit("generate_packets: wrote manifest", len(manifest["packets"]), sha256_file(C.PACKET_MANIFEST))
    flagged = sum(p["flagged_rows"] for p in manifest["packets"])
    print(f"Packets written: {len(manifest['packets'])} -> {C.PACKETS_DIR.relative_to(C.ROOT)}/")
    print(f"Rows: {len(rows)}  |  Flagged rows: {flagged}  |  Deadline: {C.REVIEW_DEADLINE}")
    esc = [p for p in manifest["packets"] if p["escalated_from"]]
    for p in esc:
        print(f"Escalation: {p['reviewer_id']} reviews team of terminated manager(s) {p['escalated_from']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
