"""Build the certification flow diagram in two formats from one definition:

  docs/certification_flow.drawio  editable in draw.io / diagrams.net
  docs/certification_flow.png     embedded in the README

Usage:  python src/make_flow_diagram.py
"""
from __future__ import annotations

# Only used to ESCAPE text we write; no XML is parsed, so XXE does not apply.
from xml.sax.saxutils import escape  # nosec B406

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
from matplotlib.patches import FancyArrowPatch, FancyBboxPatch  # noqa: E402

import config as C  # noqa: E402

# (title, script / evidence, fill color)
STEPS = [
    ("Data export", "HR roster + POS, Payroll, AP\nSHA-256 hashed", "#DDEBF7"),
    ("Validation", "validation.py\nschema, types, duplicates", "#DDEBF7"),
    ("Risk analysis", "analyzer.py\n5 checks -> PCI-DSS / NIST", "#DDEBF7"),
    ("Packets sent to managers", "generate_packets.py\ndirect reports only", "#FFF2CC"),
    ("Manager decisions", "Keep / Revoke + justification\nprocess_decisions.py", "#FFF2CC"),
    ("Remediation tickets", "create_tickets.py\nJira, no names", "#F8CBAD"),
    ("Access removed", "IT closes ticket\nwith proof attached", "#F8CBAD"),
    ("Audit evidence retained", "audit.log, hashes, reports\ncleanup.py after 90 days", "#E2EFDA"),
]
BOX_W, BOX_H, GAP_X, GAP_Y = 230, 90, 50, 70
NAVY = "#1F3864"


def positions():
    """Serpentine layout: row 1 left->right, row 2 right->left."""
    pos = []
    for i in range(len(STEPS)):
        row, col = divmod(i, 4)
        if row == 1:
            col = 3 - col
        pos.append((40 + col * (BOX_W + GAP_X), 60 + row * (BOX_H + GAP_Y)))
    return pos


def write_drawio(path):
    cells = ['<mxCell id="0"/>', '<mxCell id="1" parent="0"/>']
    for i, ((title, sub, fill), (x, y)) in enumerate(zip(STEPS, positions())):
        label = escape(f"<b>{i + 1}. {title}</b><br><font style='font-size:10px'>"
                       f"{sub.replace(chr(10), '<br>')}</font>")
        cells.append(
            f'<mxCell id="s{i}" value="{label}" style="rounded=1;whiteSpace=wrap;html=1;'
            f'fillColor={fill};strokeColor={NAVY};fontColor=#000000;arcSize=12;" vertex="1" parent="1">'
            f'<mxGeometry x="{x}" y="{y}" width="{BOX_W}" height="{BOX_H}" as="geometry"/></mxCell>')
    for i in range(len(STEPS) - 1):
        cells.append(
            f'<mxCell id="e{i}" style="edgeStyle=orthogonalEdgeStyle;rounded=0;html=1;'
            f'strokeColor={NAVY};strokeWidth=2;endArrow=block;endFill=1;" edge="1" parent="1" '
            f'source="s{i}" target="s{i + 1}"><mxGeometry relative="1" as="geometry"/></mxCell>')
    xml = ('<mxfile host="app.diagrams.net"><diagram id="flow" name="Certification Flow">'
           '<mxGraphModel dx="1200" dy="600" grid="1" gridSize="10" page="1" pageWidth="1169" '
           f'pageHeight="500"><root>{"".join(cells)}</root></mxGraphModel></diagram></mxfile>')
    path.write_text(xml, encoding="utf-8")


def write_png(path):
    pos = positions()
    W = 40 * 2 + 4 * BOX_W + 3 * GAP_X
    H = 60 + 2 * BOX_H + GAP_Y + 50
    fig, ax = plt.subplots(figsize=(W / 80, H / 80), dpi=160)
    ax.set_xlim(0, W)
    ax.set_ylim(H, 0)
    ax.axis("off")
    ax.text(W / 2, 28, "Quarterly Access Certification Flow", ha="center", va="center",
            fontsize=15, fontweight="bold", color=NAVY, family="DejaVu Sans")
    for i, ((title, sub, fill), (x, y)) in enumerate(zip(STEPS, pos)):
        ax.add_patch(FancyBboxPatch((x, y), BOX_W, BOX_H, boxstyle="round,pad=0,rounding_size=12",
                                    fc=fill, ec=NAVY, lw=1.6))
        ax.text(x + BOX_W / 2, y + 26, f"{i + 1}. {title}", ha="center", va="center",
                fontsize=9.3, fontweight="bold", color="#1A1A1A")
        ax.text(x + BOX_W / 2, y + 60, sub, ha="center", va="center", fontsize=8.3,
                color="#404040", linespacing=1.4)
    for i in range(len(STEPS) - 1):
        (x1, y1), (x2, y2) = pos[i], pos[i + 1]
        if y1 == y2:  # same row
            start = (x1 + BOX_W, y1 + BOX_H / 2) if x2 > x1 else (x1, y1 + BOX_H / 2)
            end = (x2, y2 + BOX_H / 2) if x2 > x1 else (x2 + BOX_W, y2 + BOX_H / 2)
        else:  # drop down to the next row
            start, end = (x1 + BOX_W / 2, y1 + BOX_H), (x2 + BOX_W / 2, y2)
        ax.add_patch(FancyArrowPatch(start, end, arrowstyle="-|>", mutation_scale=16,
                                     color=NAVY, lw=2))
    legend = [("#DDEBF7", "Ingest & analyze"), ("#FFF2CC", "Certify"),
              ("#F8CBAD", "Remediate"), ("#E2EFDA", "Evidence")]
    lx = 40
    for color, label in legend:
        ax.add_patch(FancyBboxPatch((lx, H - 30), 16, 12, boxstyle="round,pad=0", fc=color, ec=NAVY, lw=1))
        ax.text(lx + 22, H - 24, label, va="center", fontsize=8.5, color="#404040")
        lx += 50 + 8.5 * len(label)
    ax.text(W - 40, H - 24, C.CONFIDENTIAL, ha="right", va="center", fontsize=8, color="#C00000")
    fig.savefig(path, bbox_inches="tight", facecolor="white")
    plt.close(fig)


if __name__ == "__main__":
    C.DOCS_DIR.mkdir(parents=True, exist_ok=True)
    write_drawio(C.DOCS_DIR / "certification_flow.drawio")
    write_png(C.DOCS_DIR / "certification_flow.png")
    print("Wrote docs/certification_flow.drawio and docs/certification_flow.png")
