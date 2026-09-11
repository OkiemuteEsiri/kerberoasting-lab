# Example Kerberos Service-Account Exposure Assessment

> Fictional example generated for portfolio demonstration. Names, systems, owners, and evidence are synthetic.

## Executive summary

The synthetic review identified one high-priority legacy ERP service identity with multiple compounding weaknesses: RC4 compatibility, an aged password, privileged rights, interactive logon, no managed rotation, and critical-service context. A reporting-service identity demonstrates a more moderate exposure driven primarily by credential age and unmanaged rotation.

## Prioritized observations

| Account | Illustrative priority | Main drivers | Recommended action |
|---|---:|---|---|
| `svc_legacy_erp` | Critical | RC4, aged credential, privilege, interactive logon, critical service | Validate AES compatibility, rotate credential, reduce privilege, restrict logon, assess gMSA |
| `svc_sql_reporting` | Medium/High | aged credential, unmanaged identity, high-criticality service | Rotate credential and assess gMSA migration |
| `gmsa_webfarm$` | Low | managed rotation, AES, no interactive logon | Maintain review cadence |

## Validation expectations

Closure requires a documented change reference, owner approval, credential-rotation evidence, encryption validation, privilege review, interactive-logon review, and post-change authentication evidence. A remediation ticket alone is not treated as proof of closure.

## Threat context

The control weaknesses are mapped to MITRE ATT&CK **T1558.003 (Kerberoasting)** and **T1078 (Valid Accounts)** for defensive prioritization. This report does not claim that either technique occurred.
