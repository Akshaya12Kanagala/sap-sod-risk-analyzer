"""
SAP Segregation of Duties (SoD) Risk Analyzer
-----------------------------------------------
A lightweight simulation of what SAP GRC Access Control's "Access Risk
Analysis" module does: cross-reference which SAP transaction codes (tcodes)
each user can execute (via their assigned roles), then flag any user who
holds BOTH sides of a known SoD conflict rule.

Usage:
    python sod_analyzer.py
Outputs:
    - Console summary
    - sod_violations_report.csv  (detailed findings, audit-style)
    - risk_by_user_chart.png     (visual risk summary)
"""

import csv
from collections import defaultdict

ROLES_FILE = "roles_transactions.csv"
USER_ROLES_FILE = "user_roles.csv"
SOD_RULES_FILE = "sod_rules.csv"
REPORT_FILE = "sod_violations_report.csv"
CHART_FILE = "risk_by_user_chart.png"


def load_role_tcode_map():
    role_map = defaultdict(set)
    with open(ROLES_FILE, newline="") as f:
        for row in csv.DictReader(f):
            role_map[row["role"]].add(row["tcode"])
    return role_map


def load_user_roles():
    users = {}
    with open(USER_ROLES_FILE, newline="") as f:
        for row in csv.DictReader(f):
            uid = row["user_id"]
            if uid not in users:
                users[uid] = {"name": row["user_name"], "roles": set()}
            users[uid]["roles"].add(row["role"])
    return users


def load_sod_rules():
    with open(SOD_RULES_FILE, newline="") as f:
        return list(csv.DictReader(f))


def build_user_tcode_access(users, role_tcode_map):
    for uid, info in users.items():
        tcodes = set()
        for role in info["roles"]:
            tcodes |= role_tcode_map.get(role, set())
        info["tcodes"] = tcodes
    return users


def analyze(users, rules):
    findings = []
    for uid, info in users.items():
        for rule in rules:
            t1, t2 = rule["tcode_1"], rule["tcode_2"]
            if t1 in info["tcodes"] and t2 in info["tcodes"]:
                findings.append({
                    "user_id": uid,
                    "user_name": info["name"],
                    "risk_id": rule["risk_id"],
                    "risk_level": rule["risk_level"],
                    "conflicting_tcodes": f"{t1} + {t2}",
                    "business_risk": rule["business_risk_description"],
                })
    return findings


def write_report(findings):
    with open(REPORT_FILE, "w", newline="") as f:
        fieldnames = ["user_id", "user_name", "risk_id", "risk_level",
                      "conflicting_tcodes", "business_risk"]
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(findings)


def print_summary(findings):
    level_order = {"High": 0, "Medium": 1, "Low": 2}
    findings_sorted = sorted(findings, key=lambda x: level_order.get(x["risk_level"], 3))

    print("=" * 78)
    print("SAP SEGREGATION OF DUTIES (SoD) RISK ANALYSIS - SUMMARY REPORT")
    print("=" * 78)
    print(f"{'User':<10} {'Name':<12} {'Risk':<8} {'Level':<8} {'Conflict'}")
    print("-" * 78)
    for f in findings_sorted:
        print(f"{f['user_id']:<10} {f['user_name']:<12} {f['risk_id']:<8} "
              f"{f['risk_level']:<8} {f['conflicting_tcodes']}")
    print("-" * 78)

    by_level = defaultdict(int)
    for f in findings:
        by_level[f["risk_level"]] += 1
    print(f"Total violations: {len(findings)}  "
          f"(High: {by_level['High']}, Medium: {by_level['Medium']}, Low: {by_level['Low']})")
    print(f"\nFull detail written to: {REPORT_FILE}")


def make_chart(findings, users):
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    counts = defaultdict(int)
    for f in findings:
        counts[f["user_name"]] += 1
    for info in users.values():
        counts.setdefault(info["name"], 0)

    names = sorted(counts.keys(), key=lambda n: -counts[n])
    values = [counts[n] for n in names]
    colors = ["#c0392b" if v >= 2 else "#e67e22" if v == 1 else "#27ae60" for v in values]

    plt.figure(figsize=(9, 5))
    plt.bar(names, values, color=colors)
    plt.title("SoD Violations by User")
    plt.ylabel("Number of SoD Conflicts")
    plt.xticks(rotation=40, ha="right")
    plt.tight_layout()
    plt.savefig(CHART_FILE, dpi=150)
    print(f"Chart written to: {CHART_FILE}")


def main():
    role_tcode_map = load_role_tcode_map()
    users = load_user_roles()
    rules = load_sod_rules()

    users = build_user_tcode_access(users, role_tcode_map)
    findings = analyze(users, rules)

    print_summary(findings)
    write_report(findings)
    make_chart(findings, users)


if __name__ == "__main__":
    main()