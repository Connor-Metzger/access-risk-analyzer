"""Access review dashboard (local only).

Run:  streamlit run src/dashboard.py --server.address 127.0.0.1

The repo's .streamlit/config.toml also binds to 127.0.0.1, and the app
refuses to render if it detects any other bind address.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import altair as alt
import pandas as pd
import streamlit as st

sys.path.insert(0, str(Path(__file__).resolve().parent))
import config as C  # noqa: E402
from analyzer import run_analysis  # noqa: E402
from common import audit, read_banner_csv  # noqa: E402

st.set_page_config(page_title="Access Review Dashboard", layout="wide")

# --- Requirement 11: refuse to serve on anything but localhost -------------
if st.get_option("server.address") not in ("127.0.0.1", "localhost"):
    st.error("This dashboard must run on 127.0.0.1 only. "
             "Restart with: streamlit run src/dashboard.py --server.address 127.0.0.1")
    st.stop()

st.markdown(f"<div style='background:#C00000;color:white;padding:6px 12px;font-weight:600;"
            f"border-radius:4px'>{C.CONFIDENTIAL.upper()}</div>", unsafe_allow_html=True)
st.title("Quarterly Access Review")
st.caption(f"{C.COMPANY} · as of {C.AS_OF_DATE} · review deadline {C.REVIEW_DEADLINE} · "
           "synthetic data")


@st.cache_data(show_spinner="Analyzing access data...")
def load_findings():
    hr, _, _, accounts, findings, _, _ = run_analysis()
    audit("dashboard: loaded findings", len(findings))
    # The dashboard never shows usernames or names: account_ref + employee_id only.
    cols = ["finding_id", "issue_type", "severity", "control_id", "application", "account_ref",
            "employee_id", "department", "store_location", "detail", "days_since_login"]
    findings = findings[cols].copy()
    findings["department"] = findings["department"].replace("", "(no HR record)")
    findings["store_location"] = findings["store_location"].replace("", "(no HR record)")
    return findings, hr[["employee_id", "department"]], len(accounts)


@st.cache_data
def load_campaign():
    if not (C.CAMPAIGN_ROWS_CSV.exists() and C.PACKET_MANIFEST.exists()):
        return None, None
    rows = read_banner_csv(C.CAMPAIGN_ROWS_CSV)
    manifest = json.loads(C.PACKET_MANIFEST.read_text())
    issued = pd.DataFrame([{"reviewer_id": p["reviewer_id"], "row_id": r}
                           for p in manifest["packets"] for r in p["row_ids"]])
    return rows, issued


findings, hr_dept, n_accounts = load_findings()
rows, issued = load_campaign()

# --- Filters ---------------------------------------------------------------
with st.sidebar:
    st.header("Filters")
    depts = st.multiselect("Department", sorted(findings["department"].unique()))
    stores = st.multiselect("Store", sorted(findings["store_location"].unique()))
    apps = st.multiselect("Application", sorted(C.APPLICATIONS))


def apply(df: pd.DataFrame) -> pd.DataFrame:
    if depts:
        df = df[df["department"].isin(depts)]
    if stores:
        df = df[df["store_location"].isin(stores)]
    if apps:
        df = df[df["application"].str.split(" + ", regex=False).map(lambda a: bool(set(a) & set(apps)))]
    return df


f = apply(findings)

# --- Headline metrics ------------------------------------------------------
c1, c2, c3, c4 = st.columns(4)
c1.metric("Accounts reviewed", n_accounts)
c2.metric("Findings (filtered)", len(f))
c3.metric("High severity", int((f["severity"] == "High").sum()))

if rows is not None:
    r = rows.merge(hr_dept, on="employee_id", how="left")
    r["department"] = r["department"].fillna("(no HR record)")
    r["store_location"] = r["store_location"].replace("", "(no HR record)")
    r = apply(r)
    total_issued = len(issued) if not (depts or stores or apps) else None
    decided = int(r["decision"].isin(["Keep", "Revoke"]).sum())
    revoked = int((r["decision"] == "Revoke").sum())
    denom = total_issued if total_issued is not None else len(r)
    c4.metric("Campaign completion", f"{decided / max(denom, 1):.0%}",
              help="Rows with a Keep/Revoke decision ÷ rows issued")
else:
    c4.metric("Campaign completion", "n/a", help="Run process_decisions.py to populate")

# --- Charts ----------------------------------------------------------------
SEV_SCALE = alt.Scale(domain=["High", "Medium", "Low"], range=["#C00000", "#E6B800", "#70AD47"])


def hbar(df: pd.DataFrame, y: str, title: str, color_by_sev: bool = False, height: int = 230):
    """Horizontal bar chart with full-width labels and severity colors."""
    enc = {"x": alt.X("count:Q", title="Findings", axis=alt.Axis(tickMinStep=1, format="d")),
           "y": alt.Y(f"{y}:N", title=None, sort="-x", axis=alt.Axis(labelLimit=260))}
    if color_by_sev:
        enc["color"] = alt.Color("severity:N", scale=SEV_SCALE, title=None, legend=alt.Legend(orient="top"))
        enc["order"] = alt.Order("sev_rank:Q")
    else:
        enc["color"] = alt.value("#1F3864")
    n = max(df[y].nunique(), 1)
    h = max(height, 46 * n)
    chart = alt.Chart(df, title=title).mark_bar().encode(**enc).properties(height=h)
    st.altair_chart(chart, width="stretch", height=h + 90)


st.subheader("Findings by type and severity")
left, right = st.columns([3, 2])
with left:
    d = f.groupby(["issue_type", "severity"]).size().rename("count").reset_index()
    d["sev_rank"] = d["severity"].map(C.SEVERITY_ORDER)
    hbar(d, "issue_type", "By finding type", color_by_sev=True, height=260)
with right:
    d = f["severity"].value_counts().reindex(["High", "Medium", "Low"], fill_value=0)
    d = d.rename("count").rename_axis("severity").reset_index()
    chart = (alt.Chart(d, title="By severity").mark_bar()
             .encode(x=alt.X("severity:N", sort=["High", "Medium", "Low"], title=None,
                             axis=alt.Axis(labelAngle=0)),
                     y=alt.Y("count:Q", title="Findings", axis=alt.Axis(tickMinStep=1, format="d")),
                     color=alt.Color("severity:N", scale=SEV_SCALE, legend=None))
             .properties(height=290))
    st.altair_chart(chart, width="stretch")

a, b = st.columns(2)
with a:
    d = f["application"].value_counts().rename("count").rename_axis("application").reset_index()
    hbar(d, "application", "By application", height=180)
with b:
    d = f["control_id"].value_counts().rename("count").rename_axis("control").reset_index()
    hbar(d, "control", "By control violated", height=180)

# --- Campaign progress -----------------------------------------------------
st.subheader("Certification campaign progress")
if rows is None:
    st.info("No campaign data yet. Run simulate_decisions.py (demo) or collect real packets, "
            "then process_decisions.py.")
else:
    m1, m2, m3 = st.columns(3)
    m1.metric("Rows decided", f"{decided} / {denom}")
    m2.metric("Revocation rate", f"{revoked / max(decided, 1):.1%}", help="Revoked ÷ decided")
    flagged = r[r["flags"] != ""]
    fr = int((flagged["decision"] == "Revoke").sum())
    m3.metric("Flagged rows remediated", f"{fr} / {len(flagged)}")
    per = (r.groupby("reviewer_id")["decision"]
           .agg(decided=lambda s: s.isin(["Keep", "Revoke"]).sum(),
                revoked=lambda s: (s == "Revoke").sum()))
    if total_issued is not None:
        per = per.reindex(issued["reviewer_id"].unique(), fill_value=0)
        per["issued"] = issued.groupby("reviewer_id").size()
    else:
        per["issued"] = r.groupby("reviewer_id").size()
    per["completion %"] = (100 * per["decided"] / per["issued"]).round(0)
    d = per.reset_index().rename(columns={"index": "reviewer_id"})
    d["status"] = pd.cut(d["completion %"], [-1, 0, 99.9, 100], labels=["Not returned", "Partial", "Complete"])
    chart = (alt.Chart(d, title="Completion by reviewer").mark_bar()
             .encode(x=alt.X("reviewer_id:N", title=None, sort="y", axis=alt.Axis(labelAngle=-45)),
                     y=alt.Y("completion %:Q", scale=alt.Scale(domain=[0, 100])),
                     color=alt.Color("status:N", scale=alt.Scale(
                         domain=["Complete", "Partial", "Not returned"],
                         range=["#1F3864", "#E6B800", "#C00000"]), legend=alt.Legend(orient="bottom")))
             .properties(height=280))
    st.altair_chart(chart, width="stretch")
    st.caption("Reviewer IDs only. A reviewer at 0% has not returned their packet.")

# --- Detail table ----------------------------------------------------------
with st.expander(f"Finding detail ({len(f)})"):
    st.dataframe(f, hide_index=True, width="stretch")
