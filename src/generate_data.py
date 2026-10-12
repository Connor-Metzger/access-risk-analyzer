"""Generate synthetic HR and application data for Keystone Fuel & Market.

All people, usernames, and stores are fake (Faker, fixed seed). The script
plants a known set of access problems and records them in
data/planted_issues.csv so the analyzer's accuracy can be measured.

Usage:  python src/generate_data.py
"""
from __future__ import annotations

import random
import re
import unicodedata
from datetime import timedelta

import pandas as pd
from faker import Faker

import config as C
from common import audit, sha256_file

# Seeded PRNG is intentional: reproducible synthetic data, not security use.
rng = random.Random(C.SEED)  # nosec B311
fake = Faker("en_US")
Faker.seed(C.SEED)

STORES = [f"Store {n:03d}" for n in range(101, 111)]  # 10 stores
HQ = "Corporate HQ"

employees: list[dict] = []
_next_id = 10001
_usernames: set[str] = set()


def _ascii(text: str) -> str:
    return unicodedata.normalize("NFKD", text).encode("ascii", "ignore").decode()


def new_employee(title: str, dept: str, manager_id: str, location: str) -> dict:
    global _next_id
    first, last = fake.first_name(), fake.last_name()
    emp = {
        "employee_id": f"E{_next_id}",
        "name": f"{first} {last}",
        "job_title": title,
        "department": dept,
        "manager_id": manager_id,
        "store_location": location,
        "status": "active",
        "termination_date": "",
    }
    base = re.sub(r"[^a-z]", "", _ascii(first[0] + last).lower())
    username, n = base, 1
    while username in _usernames:
        n += 1
        username = f"{base}{n}"
    _usernames.add(username)
    emp["_username"] = username  # internal only; not written to the HR file
    _next_id += 1
    employees.append(emp)
    return emp


def days_ago(n: int) -> str:
    return (C.AS_OF_DATE - timedelta(days=n)).isoformat()


# ---------------------------------------------------------------------------
# 1. Org chart (~200 people)
# ---------------------------------------------------------------------------
president = new_employee("President", "Executive", "", HQ)
vp_ops = new_employee("VP Store Operations", "Store Operations", president["employee_id"], HQ)
dms = [new_employee("District Manager", "Store Operations", vp_ops["employee_id"], HQ) for _ in range(2)]

controller = new_employee("Controller", "Finance", president["employee_id"], HQ)
ap_mgr = new_employee("AP Manager", "Finance", controller["employee_id"], HQ)
ap_clerks = [new_employee("AP Clerk", "Finance", ap_mgr["employee_id"], HQ) for _ in range(4)]
vendor_spec = new_employee("Vendor Master Specialist", "Finance", ap_mgr["employee_id"], HQ)
pay_mgr = new_employee("Payroll Manager", "Finance", controller["employee_id"], HQ)
pay_specs = [new_employee("Payroll Specialist", "Finance", pay_mgr["employee_id"], HQ) for _ in range(4)]

hr_dir = new_employee("HR Director", "Human Resources", president["employee_id"], HQ)
hr_gens = [new_employee("HR Generalist", "Human Resources", hr_dir["employee_id"], HQ) for _ in range(4)]
it_dir = new_employee("IT Director", "Information Technology", president["employee_id"], HQ)
it_staff = [new_employee("IT Support Specialist", "Information Technology", it_dir["employee_id"], HQ)
            for _ in range(5)]

store_staff: dict[str, dict] = {}
remaining = 200 - len(employees)
for i, store in enumerate(STORES):
    dm = dms[0] if i < 5 else dms[1]
    sm = new_employee("Store Manager", "Store Operations", dm["employee_id"], store)
    am = new_employee("Assistant Store Manager", "Store Operations", sm["employee_id"], store)
    n_assoc = remaining // len(STORES) - 2 + (1 if i < remaining % len(STORES) else 0)
    leads, assocs = [], []
    for j in range(n_assoc):
        if j < 2:
            leads.append(new_employee("Shift Lead", "Store Operations", sm["employee_id"], store))
        else:
            title = "Cashier" if rng.random() < 0.35 else "Store Associate"
            assocs.append(new_employee(title, "Store Operations", sm["employee_id"], store))
    store_staff[store] = {"sm": sm, "am": am, "leads": leads, "assocs": assocs}

if len(employees) != 200:
    raise RuntimeError(f"Expected 200 employees, generated {len(employees)}")

# ---------------------------------------------------------------------------
# 2. Baseline access by role (the "clean" state)
# ---------------------------------------------------------------------------
ROLE_ACCESS = {
    "Store Associate": {"POS": ["POS: Cashier"]},
    "Cashier": {"POS": ["POS: Cashier"]},
    "Shift Lead": {"POS": ["POS: Cashier", "POS: Void Transaction", "POS: Issue Refund"]},
    "Assistant Store Manager": {
        "POS": ["POS: Cashier", "POS: Void Transaction", "POS: Issue Refund", "POS: Price Override"],
        "Payroll": ["Payroll: Enter Timecards"],
    },
    "Store Manager": {
        "POS": ["POS: Cashier", "POS: Price Override", "POS: Approve Cash Reconciliation",
                "POS: Store Manager Admin"],
        "Payroll": ["Payroll: View Employee", "Payroll: Enter Timecards"],
    },
    "District Manager": {"POS": ["POS: Approve Cash Reconciliation"], "Payroll": ["Payroll: View Employee"]},
    "VP Store Operations": {"Payroll": ["Payroll: View Employee"]},
    "AP Clerk": {"Accounts Payable": ["AP: View Invoices", "AP: Enter Invoice"]},
    "Vendor Master Specialist": {"Accounts Payable": ["AP: View Invoices", "AP: Create Vendor"]},
    "AP Manager": {"Accounts Payable": ["AP: View Invoices", "AP: Approve Payment"]},
    "Payroll Specialist": {"Payroll": ["Payroll: View Employee", "Payroll: Enter Timecards",
                                       "Payroll: Add Employee", "Payroll: Edit Pay Rate"]},
    "Payroll Manager": {"Payroll": ["Payroll: View Employee", "Payroll: Run Payroll",
                                    "Payroll: Approve Payroll"]},
    "Controller": {"Accounts Payable": ["AP: View Invoices"], "Payroll": ["Payroll: View Employee"]},
    "HR Director": {"Payroll": ["Payroll: View Employee"]},
    "HR Generalist": {"Payroll": ["Payroll: View Employee", "Payroll: Add Employee"]},
}

# accounts[(employee_id, application)] = {"username", "entitlements": set, "last_login"}
accounts: dict[tuple[str, str], dict] = {}
for emp in employees:
    for app, ents in ROLE_ACCESS.get(emp["job_title"], {}).items():
        accounts[(emp["employee_id"], app)] = {
            "username": emp["_username"],
            "employee_id": emp["employee_id"],
            "application": app,
            "entitlements": set(ents),
            "last_login": days_ago(rng.randint(0, 60)),
        }

# ---------------------------------------------------------------------------
# 3. Natural, correctly handled terminations (no accounts left = not an issue)
# ---------------------------------------------------------------------------
used: set[str] = set()
all_assocs = [e for s in store_staff.values() for e in s["assocs"]]
for emp in rng.sample(all_assocs, 12):
    emp["status"] = "terminated"
    emp["termination_date"] = days_ago(rng.randint(15, 330))
    for app in list(C.APPLICATIONS):
        accounts.pop((emp["employee_id"], app), None)
    used.add(emp["employee_id"])

# A store manager who left properly (no accounts), but HR never re-pointed
# their team to a new manager. Not an access finding; it's a data-quality
# warning the analyzer must handle when routing packets.
orphaned_team_sm = store_staff["Store 109"]["sm"]
orphaned_team_sm["status"] = "terminated"
orphaned_team_sm["termination_date"] = days_ago(21)
for app in list(C.APPLICATIONS):
    accounts.pop((orphaned_team_sm["employee_id"], app), None)
used.add(orphaned_team_sm["employee_id"])

# ---------------------------------------------------------------------------
# 4. Planted problems + answer key
# ---------------------------------------------------------------------------
answer_key: list[dict] = []


def plant(issue_type: str, acct: dict, detail: str = "", note: str = "") -> None:
    answer_key.append({
        "issue_type": issue_type,
        "username": acct["username"],
        "employee_id": acct["employee_id"],
        "application": acct["application"],
        "detail": detail,
        "note": note,
    })


def pick(pool: list[dict], must_have_app: str | None = None) -> dict:
    candidates = [e for e in pool if e["employee_id"] not in used and e["status"] == "active"
                  and (must_have_app is None or (e["employee_id"], must_have_app) in accounts)]
    emp = rng.choice(candidates)
    used.add(emp["employee_id"])
    return emp


active_assocs = [e for e in all_assocs if e["status"] == "active"]
store_ams = [s["am"] for k, s in store_staff.items() if k != "Store 109"]

# 4a. Terminated users who still have active accounts (PCI-DSS 8.2.5)
for emp, note in [
    (pick(active_assocs), "Left recently; POS account never disabled"),
    (pick(active_assocs), "Login AFTER termination date (possible shared credential)"),
    (pick(ap_clerks), "AP access survived termination"),
    (pick(store_ams), "Two applications left enabled"),
]:
    term_days = rng.randint(20, 60)
    emp["status"] = "terminated"
    emp["termination_date"] = days_ago(term_days)
    for app in C.APPLICATIONS:
        acct = accounts.get((emp["employee_id"], app))
        if not acct:
            continue
        if "AFTER" in note:
            acct["last_login"] = days_ago(term_days - 5)
        else:
            acct["last_login"] = days_ago(term_days + rng.randint(1, 10))
        plant(C.TERMINATED, acct, note=note)

# One person who is BOTH terminated and dormant (tests multi-finding accounts)
emp = pick(pay_specs)
emp["status"] = "terminated"
emp["termination_date"] = days_ago(200)
acct = accounts[(emp["employee_id"], "Payroll")]
acct["last_login"] = days_ago(205)
plant(C.TERMINATED, acct, note="Terminated 200 days ago; also dormant")
plant(C.DORMANT, acct, note="Terminated 200 days ago; also dormant")

# 4b. Dormant accounts on active employees (PCI-DSS 8.2.6)
for pool, app, age in [
    (active_assocs, "POS", 120),
    (active_assocs, "POS", 245),
    ([s["leads"][0] for s in store_staff.values()], "POS", 97),
    (hr_gens, "Payroll", 150),
    ([controller], "Accounts Payable", 310),
]:
    emp = pick(pool, must_have_app=app)
    acct = accounts[(emp["employee_id"], app)]
    acct["last_login"] = days_ago(age)
    plant(C.DORMANT, acct, note=f"No login for {age} days")

# 4c. SoD violations (NIST AC-5)
sod_plants = [
    (ap_clerks, "Accounts Payable", ["AP: Create Vendor", "AP: Approve Payment"], "SOD-01",
     "Clerk can create a vendor and pay it"),
    ([vendor_spec], "Accounts Payable", ["AP: Approve Payment"], "SOD-01",
     "Vendor specialist granted payment approval"),
    (store_ams, "POS", ["POS: Approve Cash Reconciliation"], "SOD-02",
     "Can issue refunds and approve the drawer count that hides them"),
    (pay_specs, "Payroll", ["Payroll: Approve Payroll"], "SOD-03",
     "Can change pay rates and approve the payroll"),
]
for pool, app, extra, rule, note in sod_plants:
    emp = pick(pool, must_have_app=app)
    acct = accounts[(emp["employee_id"], app)]
    acct["entitlements"].update(extra)
    plant(C.SOD, acct, detail=rule, note=note)

# 4d. Store associates holding manager-level permissions (NIST AC-6)
for ent, note in [
    ("POS: Store Manager Admin", "Covered for manager on vacation; never removed"),
    ("POS: Approve Cash Reconciliation", "Copied access from manager's profile"),
    ("POS: Price Override", "Granted during holiday rush"),
    ("POS: Price Override", "Cashier with price override"),
]:
    pool = [e for e in active_assocs if (e["job_title"] == "Cashier") == ("Cashier" in note)]
    emp = pick(pool, must_have_app="POS")
    acct = accounts[(emp["employee_id"], "POS")]
    acct["entitlements"].add(ent)
    plant(C.EXCESS, acct, detail=ent, note=note)

# 4e. Orphaned accounts: no matching HR record (NIST AC-2)
orphans = [
    ("svc_possync", "", "POS", ["POS: Store Manager Admin"], "Service account with no named owner"),
    ("temp.auditor", "", "Accounts Payable", ["AP: View Invoices", "AP: Approve Payment"],
     "Contractor account; contract ended, never in HR"),
    ("mhollis_old", "E19998", "Payroll", ["Payroll: View Employee", "Payroll: Edit Pay Rate"],
     "Points to an employee ID that doesn't exist"),
    # Formula-injection test payload: proves output sanitization works.
    ('=HYPERLINK("https://example.invalid","Click me")', "E19999", "POS", ["POS: Cashier"],
     "Malicious username; must be neutralized in every output"),
]
for user, eid, app, ents, note in orphans:
    acct = {"username": user, "employee_id": eid, "application": app,
            "entitlements": set(ents), "last_login": days_ago(rng.randint(1, 30))}
    accounts[(f"ORPHAN:{user}", app)] = acct
    plant(C.ORPHAN, acct, note=note)

# ---------------------------------------------------------------------------
# 5. Decoys: look suspicious but are NOT violations (tests false positives)
# ---------------------------------------------------------------------------
decoy = pick(active_assocs, must_have_app="POS")
accounts[(decoy["employee_id"], "POS")]["last_login"] = days_ago(90)  # exactly 90, not >90

# ---------------------------------------------------------------------------
# 6. Write files
# ---------------------------------------------------------------------------
C.DATA_DIR.mkdir(parents=True, exist_ok=True)

hr_df = pd.DataFrame([{k: v for k, v in e.items() if not k.startswith("_")} for e in employees])
hr_df = hr_df.sample(frac=1, random_state=C.SEED).reset_index(drop=True)

rows = []
for acct in accounts.values():
    for ent in sorted(acct["entitlements"]):
        rows.append({"username": acct["username"], "employee_id": acct["employee_id"],
                     "application": acct["application"], "entitlement": ent,
                     "last_login_date": acct["last_login"]})
acct_df = pd.DataFrame(rows).sample(frac=1, random_state=C.SEED).reset_index(drop=True)

sod_df = pd.DataFrame([
    {"rule_id": "SOD-01", "entitlement_a": "AP: Create Vendor", "entitlement_b": "AP: Approve Payment",
     "risk_description": "Fictitious vendor fraud: one person can create a vendor and pay it",
     "severity": "High"},
    {"rule_id": "SOD-02", "entitlement_a": "POS: Issue Refund",
     "entitlement_b": "POS: Approve Cash Reconciliation",
     "risk_description": "Refund fraud concealment: one person can refund and approve the drawer count",
     "severity": "High"},
    {"rule_id": "SOD-03", "entitlement_a": "Payroll: Edit Pay Rate", "entitlement_b": "Payroll: Approve Payroll",
     "risk_description": "Pay manipulation: one person can change pay and approve the payroll",
     "severity": "High"},
    {"rule_id": "SOD-04", "entitlement_a": "Payroll: Add Employee", "entitlement_b": "Payroll: Run Payroll",
     "risk_description": "Ghost employee: one person can add a worker and run payroll",
     "severity": "High"},
])

key_df = pd.DataFrame(answer_key)

for df, path in [(hr_df, C.HR_FILE), (acct_df, C.ACCOUNTS_FILE), (sod_df, C.SOD_FILE),
                 (key_df, C.ANSWER_KEY_FILE)]:
    df.to_csv(path, index=False)
    audit(f"generate_data: wrote {path.name}", len(df), sha256_file(path))

print(f"HR roster:      {len(hr_df)} employees ({(hr_df.status == 'terminated').sum()} terminated)")
print(f"App accounts:   {len(acct_df)} entitlement rows across "
      f"{acct_df.groupby(['application', 'username']).ngroups} accounts")
print(f"SoD rules:      {len(sod_df)}")
print(f"Planted issues: {len(key_df)}")
print(key_df.groupby("issue_type").size().to_string())
