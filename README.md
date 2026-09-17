# SAP Segregation of Duties (SoD) Risk Analyzer

A Python simulation of the core logic behind SAP GRC Access Control's
Access Risk Analysis (ARA) module — the same discipline EY's SAP
Security/GRC risk consulting teams deliver for clients.

## What it does
1. Reads sample SAP role → transaction code (tcode) mappings
2. Reads sample user → role assignments
3. Reads a library of known SoD conflict rules (e.g. "create vendor" +
   "run payment" = fraud risk)
4. Resolves each user's *effective* access across all their roles
5. Flags every user who holds both sides of a conflict, rates the risk
   (High/Medium/Low), and explains the business risk in plain language
6. Outputs an audit-style CSV report and a risk-by-user chart

<!-- ## Why I built it this way
Real SAP tenants aren't handed out to interns. But the actual skill EY's
SAP Security/GRC teams are hiring for isn't "can you click through PFCG" —
it's "do you understand *why* certain access combinations are dangerous,
and can you reason about access at the level of controls, not just
transactions." This project proves that understanding using tools I
already have (Python, CSV, basic data modeling) instead of claiming SAP
experience I don't yet have. -->

<!-- ## How this connects to EY specifically
- EY's Risk Consulting practice runs SAP Application Security and SAP GRC
  Access Control engagements: role design, user provisioning, access
  reviews, and SoD analysis — exactly what this script does in miniature.
- SAP is ending mainstream ECC maintenance in Dec 2027, which means the
  vast majority of SAP-run enterprises are mid-migration to S/4HANA right
  now. Every migration requires a full **redesign of security roles and
  SoD rulesets** (old ECC roles don't map 1:1 to S/4HANA), which is
  driving major demand for exactly this skill set at EY over the next
  18–24 months.
- EY's stated purpose — "building a better working world" — and its
  NextWave strategy explicitly frame trust and governance (not just
  technology delivery) as the value EY provides. SoD/access-risk work is
  literally trust-building infrastructure inside client organizations —
  it's a very direct, concrete expression of that purpose, not just a
  slogan I'm repeating back. -->

## How to run it
```
pip install matplotlib
python sod_analyzer.py
```

<!-- ## What I'd extend next 
- Cross-system SoD (SAP + non-SAP apps, like real GRC tools do)
- Mitigating controls layer (some conflicts are accepted risk with a
  compensating control — e.g. a monthly review report)
- Firefighter/emergency access logging simulation
- A simple risk-scoring model that weights by financial materiality,
  not just conflict count -->
