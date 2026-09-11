# Kerberos Service-Account Exposure Assessment Lab

Defensive Active Directory / Identity Security project for assessing Kerberos service-account exposure from **offline inventory metadata**. The project focuses on governance, prioritization, remediation, and validation rather than exploitation.

> **Safety scope:** this repository does not request Kerberos tickets, crack passwords, enumerate live domains, collect credentials, contact production systems, or execute ATT&CK techniques. All included data is synthetic.

## Problem statement

Service accounts frequently become long-lived identity risk because they can accumulate legacy encryption support, stale passwords, excessive privilege, interactive-logon rights, unclear ownership, and weak rotation practices. A useful identity-security program needs more than a list of SPNs: it needs deterministic prioritization, accountable remediation, and evidence-backed closure.

This project implements that defensive workflow.

## What the project demonstrates

- Strongly validated service-account inventory ingestion.
- Kerberos encryption-posture review, including RC4 dependency.
- Password-age and managed-identity governance.
- Privilege and interactive-logon review.
- Business criticality context.
- Deterministic 0–100 prioritization.
- MITRE ATT&CK threat-context mapping.
- Evidence-based remediation closure.
- Executive and technical Markdown reporting.
- Unit tests and least-privilege CI.

## Architecture

```text
JSON inventory
    |
    v
Validation / normalization
    |
    v
Contextual risk engine
    |
    +----> portfolio metrics
    |
    +----> prioritized findings
                |
                v
          Markdown reporting
                |
                v
       remediation validation
```

Detailed design: [`docs/architecture-methodology.md`](docs/architecture-methodology.md)

## Repository structure

```text
.
├── .github/workflows/security-ci.yml
├── data/
│   └── synthetic_service_accounts.json
├── docs/
│   └── architecture-methodology.md
├── reports/
│   └── example-assessment.md
├── src/
│   ├── assessor.py
│   ├── cli.py
│   ├── models.py
│   ├── remediation.py
│   └── report.py
└── tests/
    └── test_assessor.py
```

## Risk model

The assessment uses an explainable bounded score rather than presenting the result as CVSS. Risk increases when observable control weaknesses and business-impact factors compound.

| Factor | Example impact |
|---|---:|
| RC4 compatibility | +30 |
| Unknown encryption posture | +15 |
| Password age >365 days | +20 |
| Password age >180 days | +12 |
| Privileged service identity | +20 |
| Interactive logon allowed | +10 |
| Not managed by gMSA/equivalent | +8 |
| High/critical service context | contextual weight |

Scores are capped at 100 and translated to `critical`, `high`, `medium`, and `low` priority bands. Disabled accounts remain governance records but do not receive an active exposure score.

The model is intentionally transparent and should be tuned to an organization's identity architecture, control maturity, and risk appetite.

## MITRE ATT&CK context

The project maps findings to:

- **T1558.003 – Steal or Forge Kerberos Tickets: Kerberoasting**
- **T1078 – Valid Accounts**

These mappings explain defensive relevance. They are **not evidence that an adversary requested tickets, recovered credentials, or used an account**.

## Usage

Requirements: Python 3.11+; no third-party packages are required.

Run the synthetic assessment:

```bash
python -m src.cli data/synthetic_service_accounts.json --report assessment.md
```

Run tests:

```bash
python -m unittest discover -s tests -v
```

The CLI operates only on the local JSON file supplied to it.

## Input model

Each service-account record contains:

- account name and SPN;
- accountable owner;
- supported encryption posture;
- password age;
- privilege status;
- interactive-logon status;
- managed-identity/gMSA status;
- enabled state;
- business criticality;
- last review timestamp.

The loader fails closed on malformed records, unsupported values, missing fields, impossible timestamps, negative password ages, and duplicate account/SPN pairs.

## Remediation workflow

A high-quality identity-security finding should not close merely because a ticket says "fixed." This project models a stricter lifecycle:

1. Confirm owner and application dependency.
2. Establish maintenance window and rollback plan.
3. Validate AES support before removing legacy encryption dependency.
4. Rotate long-lived credentials or migrate eligible services to gMSA.
5. Remove unnecessary privileged group membership.
6. Restrict interactive logon for service identities.
7. Validate service authentication after change.
8. Re-run inventory and retain closure evidence.

`src/remediation.py` requires a change reference, owner approval, credential-rotation evidence, encryption validation, privilege review, interactive-logon review, and post-change authentication validation before returning a `validated` closure state.

## Example assessment

[`reports/example-assessment.md`](reports/example-assessment.md) contains a fictional recruiter-facing assessment that shows how technical weaknesses become prioritized remediation decisions without claiming real-world compromise.

## Testing

The unit suite covers:

- secure managed-account behavior;
- RC4/aged/privileged risk accumulation;
- disabled-account handling;
- score bounds;
- deterministic finding IDs;
- prioritization order;
- portfolio metrics;
- report content;
- duplicate-record rejection;
- missing-field rejection;
- invalid-encryption rejection;
- complete and incomplete remediation evidence.

The GitHub Actions workflow uses `contents: read` only, compiles the code, runs the unit suite, and generates the synthetic assessment.

## Design decisions

**Offline by design.** The project demonstrates security-engineering logic without requiring domain access or creating a dual-use ticket-request/cracking utility.

**Deterministic decisions.** Identical account/SPN evidence produces the same finding identifier and scoring outcome, improving auditability.

**Business context matters.** Identity weakness on a critical or privileged service is prioritized differently from a low-impact record.

**Validation is separate from remediation intent.** A proposed change is not treated as evidence that the control is restored.

## Limitations

- No LDAP/AD discovery or live domain enumeration.
- No Kerberos ticket acquisition or inspection.
- No password cracking or password-entropy estimation.
- No proof that a given credential is practically recoverable.
- No automated Group Policy or ACL modification.
- Synthetic data must not be interpreted as operational evidence.
- Scoring weights are illustrative, not an industry standard.

## Skills demonstrated

- Active Directory / identity-security reasoning
- Kerberos service-account governance
- Security control assessment
- Contextual risk prioritization
- Data validation and defensive Python engineering
- MITRE ATT&CK mapping
- Remediation design and validation
- Unit testing
- Security-focused CI/CD
- Executive risk communication

## Roadmap

- Add schema versioning for exported identity inventories.
- Add configurable policy profiles and organization-specific thresholds.
- Add review-age governance and exception-expiry handling.
- Add synthetic identity ownership and tiering datasets.
- Add JSON/SARIF-style machine-readable output for defensive pipelines.
- Add trend comparison between two offline inventory snapshots.

## Ethical and operational boundary

Use only data you are authorized to assess. Do not place real credentials, ticket material, confidential identity exports, client information, or production secrets in this repository.

## License

Educational and portfolio demonstration project. Add an organization-approved license before reuse in production environments.
