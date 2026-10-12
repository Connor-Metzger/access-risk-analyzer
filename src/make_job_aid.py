"""Build docs/manager_job_aid.pdf: "How to Complete Your Access Review" (one page).

Usage:  python src/make_job_aid.py
"""
from __future__ import annotations

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

import config as C

NAVY = colors.HexColor("#1F3864")
RED = colors.HexColor("#C00000")
OUT = C.DOCS_DIR / "manager_job_aid.pdf"

ss = getSampleStyleSheet()
H1 = ParagraphStyle("h1", parent=ss["Title"], fontSize=17, leading=20, textColor=NAVY, spaceAfter=2)
SUB = ParagraphStyle("sub", parent=ss["Normal"], fontSize=9, alignment=TA_CENTER,
                     textColor=colors.HexColor("#595959"), spaceAfter=6)
H2 = ParagraphStyle("h2", parent=ss["Heading2"], fontSize=11, leading=13, textColor=NAVY,
                    spaceBefore=6, spaceAfter=3)
BODY = ParagraphStyle("b", parent=ss["Normal"], fontSize=8.8, leading=11.2)
CELL = ParagraphStyle("c", parent=BODY, fontSize=8.2, leading=10)
CELLB = ParagraphStyle("cb", parent=CELL, fontName="Helvetica-Bold", textColor=colors.white)


def banner(canvas, doc):
    canvas.saveState()
    canvas.setFillColor(RED)
    canvas.rect(0, letter[1] - 0.32 * inch, letter[0], 0.32 * inch, fill=1, stroke=0)
    canvas.setFillColor(colors.white)
    canvas.setFont("Helvetica-Bold", 9)
    canvas.drawCentredString(letter[0] / 2, letter[1] - 0.21 * inch, C.CONFIDENTIAL.upper())
    canvas.setFillColor(colors.HexColor("#7F7F7F"))
    canvas.setFont("Helvetica", 7.5)
    canvas.drawCentredString(letter[0] / 2, 0.35 * inch,
                             f"{C.COMPANY} | IAM Governance | {C.CONFIDENTIAL}")
    canvas.restoreState()


def table(rows, widths, header=True, shade=None):
    data = [[Paragraph(str(c), CELLB if (header and i == 0) else CELL) for c in r]
            for i, r in enumerate(rows)]
    t = Table(data, colWidths=widths)
    style = [("VALIGN", (0, 0), (-1, -1), "TOP"),
             ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#BFBFBF")),
             ("LEFTPADDING", (0, 0), (-1, -1), 4), ("RIGHTPADDING", (0, 0), (-1, -1), 4),
             ("TOPPADDING", (0, 0), (-1, -1), 2.5), ("BOTTOMPADDING", (0, 0), (-1, -1), 2.5)]
    if header:
        style += [("BACKGROUND", (0, 0), (-1, 0), NAVY), ("TEXTCOLOR", (0, 0), (-1, 0), colors.white)]
    for (r, color) in (shade or []):
        style.append(("BACKGROUND", (0, r), (-1, r), color))
    t.setStyle(TableStyle(style))
    return t


def build():
    story = [
        Paragraph("How to Complete Your Access Review", H1),
        Paragraph(f"Quarterly access certification | Deadline: <b>{C.REVIEW_DEADLINE:%A, %B %d, %Y}</b> | "
                  "About 15 minutes for most store teams", SUB),
        Paragraph("<b>Why this matters.</b> You know what your team actually does. Auditors (PCI-DSS) "
                  "require a manager to confirm that each person's system access is still needed. "
                  "Access left behind after a role change or departure is how refund fraud, "
                  "fake vendors, and payroll fraud happen.", BODY),

        Paragraph("Five steps", H2),
        table([
            ["Step", "What to do"],
            ["1. Open", "Open the packet named <b>packet_[your ID].xlsx</b>. It lists only your direct "
                        "reports. If someone on it isn't yours, stop and tell IAM; don't review them."],
            ["2. Start with color", "Review <font color='#C00000'><b>red</b></font> (High) rows first, then "
                                    "<b>yellow</b> (Medium). The <i>flags</i> column says what's wrong."],
            ["3. Decide every row", "Pick <b>Keep</b> or <b>Revoke</b> from the dropdown in the Decision "
                                    "column. Blank rows count as incomplete."],
            ["4. Justify flagged Keeps", "If you Keep a flagged row, write <b>why</b> and <b>until when</b> "
                                         "in Justification. Unjustified Keeps are sent back."],
            ["5. Sign and return", "Type your name and today's date in the blue attestation boxes, save, "
                                   "and return the file by the deadline."],
        ], [1.35 * inch, 5.75 * inch]),

        Paragraph("What the flags mean", H2),
        table([
            ["Flag", "What it means", "Usual decision"],
            ["Terminated User - Active Access", "HR shows this person left, but the account still works.",
             "<b>Revoke.</b> Tell IAM if you think HR is wrong."],
            ["Separation of Duties", "One person holds two duties that should be split (e.g. issue refunds "
                                     "<i>and</i> approve the cash count that would reveal them).",
             "Revoke one of the two. Keep only with a named second reviewer."],
            ["Excess Privilege", "A cashier or associate holds manager-level rights (price override, "
                                 "cash reconciliation, store admin).",
             "Revoke, unless covering for you with an end date."],
            ["Inactive Account (90+ days)", "No login in over 90 days.",
             "Revoke. It can be re-requested when needed."],
            ["Orphaned Account", "No HR record matches. Reviewed by IAM, not by managers.", "n/a"],
        ], [1.6 * inch, 3.5 * inch, 2.0 * inch],
            shade=[(1, colors.HexColor("#FBE3E3")), (2, colors.HexColor("#FBE3E3"))]),

        Paragraph("Writing a good justification", H2),
        table([
            ["Accepted", "Sent back"],
            ["\"Covers night shift as acting lead through 2026-11-30. HR ticket HR-1042.\"",
             "\"Needed\" / \"OK\" / \"Approved\""],
            ["\"Seasonal; returns Nov 15. Disable until then is fine.\"", "\"Has always had this\""],
            ["\"Refund and reconciliation split: district manager co-signs counts weekly.\"",
             "Copying the same text onto every row"],
        ], [3.55 * inch, 3.55 * inch]),

        Paragraph("Please don't", H2),
        Paragraph("&bull; <b>Keep everything to finish fast.</b> 100% Keep with flagged items is detected "
                  "automatically and escalated to your district manager.<br/>"
                  "&bull; <b>Forward, print, or email the packet outside the company.</b> It contains "
                  "employee data and is Confidential.<br/>"
                  "&bull; <b>Delete or add rows.</b> Packets are checked against what was sent; edited "
                  "packets are rejected.", BODY),
        Spacer(1, 5),
        Paragraph("<b>What happens next:</b> each Revoke becomes a remediation ticket. IT removes the access "
                  "and attaches proof. You don't need to do anything else. "
                  "<b>Questions?</b> Contact IAM Governance (fictional contact for this demo).", BODY),
    ]
    C.DOCS_DIR.mkdir(parents=True, exist_ok=True)
    doc = SimpleDocTemplate(str(OUT), pagesize=letter, topMargin=0.5 * inch, bottomMargin=0.55 * inch,
                            leftMargin=0.7 * inch, rightMargin=0.7 * inch,
                            title="How to Complete Your Access Review", author="IAM Governance")
    doc.build(story, onFirstPage=banner, onLaterPages=banner)
    print(f"Wrote {OUT.relative_to(C.ROOT)}")


if __name__ == "__main__":
    build()
