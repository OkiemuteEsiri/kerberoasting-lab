# Architecture and Methodology

## Purpose

This project demonstrates a defensive Kerberos service-account exposure review. It consumes inventory-style metadata and produces prioritized findings without requesting service tickets, capturing credentials, cracking passwords, or contacting Active Directory.

## Architecture

```text
Synthetic / exported inventory
          |
          v
  Validation & normalization
          |
          v
 Contextual risk engine
          |
   +------+------+
   |             |
   v             v
Metrics       Findings
   |             |
   +------v------+
          |
          v
 Markdown report
          |
          v
 Remediation evidence review
```

## Trust boundaries

1. **Input boundary** — records are untrusted until schema and value validation succeed.
2. **Scoring boundary** — only deterministic, documented factors affect priority.
3. **Reporting boundary** — ATT&CK mappings express defensive threat context, not proof of compromise.
4. **Closure boundary** — remediation is not considered validated without explicit evidence.

## Control domains

- Kerberos encryption posture and RC4 dependency.
- Password age and rotation governance.
- gMSA/managed service account adoption.
- Privileged group membership.
- Interactive-logon rights for service identities.
- Business ownership and asset criticality.
- Post-change authentication validation.

## Risk method

The score is bounded to 0–100 and combines observable exposure conditions with business impact. RC4, aged credentials, privilege, interactive logon, unmanaged identities, and critical service context increase risk. Disabled accounts receive no active exposure score but remain governance records.

This is a prioritization model, not CVSS and not a claim of exploitability. It intentionally separates identity-control weakness from demonstrated compromise.

## MITRE ATT&CK context

- **T1558.003 – Steal or Forge Kerberos Tickets: Kerberoasting**: used to explain why SPN-bound service accounts with weak password/encryption posture deserve attention.
- **T1078 – Valid Accounts**: used to describe the potential impact of service credential compromise.

No ATT&CK technique is executed by this repository.

## Remediation lifecycle

1. Confirm owner and application dependency.
2. Establish rollback and maintenance window.
3. Validate AES support and remove legacy encryption dependency where feasible.
4. Rotate long-lived credentials or migrate eligible services to gMSA.
5. Remove unnecessary privilege.
6. Restrict interactive logon.
7. Validate service authentication after change.
8. Re-run inventory and retain closure evidence.

## Limitations

- Does not query a domain controller or LDAP.
- Does not inspect ticket material or request TGS tickets.
- Does not estimate password entropy.
- Does not prove that an account is practically crackable.
- Synthetic data is illustrative and must not be treated as production evidence.
