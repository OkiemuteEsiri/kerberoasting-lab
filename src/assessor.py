import hashlib
import json
from pathlib import Path
from typing import Iterable, List

from .models import Finding, ServiceAccount

CRITICALITY_WEIGHT = {"low": 0, "medium": 8, "high": 14, "critical": 20}


def load_accounts(path: str) -> List[ServiceAccount]:
    raw = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(raw, list):
        raise ValueError("input must be a JSON array")
    accounts: List[ServiceAccount] = []
    seen = set()
    for row in raw:
        if not isinstance(row, dict):
            raise ValueError("every record must be an object")
        required = {
            "account", "spn", "owner", "criticality", "encryption",
            "password_age_days", "privileged", "interactive_logon",
            "managed_identity", "enabled", "last_reviewed"
        }
        missing = required - row.keys()
        if missing:
            raise ValueError(f"missing fields: {sorted(missing)}")
        account = ServiceAccount(**{key: row[key] for key in required})
        account.validate()
        key = (account.account.lower(), account.spn.lower())
        if key in seen:
            raise ValueError(f"duplicate account/SPN record: {account.account} {account.spn}")
        seen.add(key)
        accounts.append(account)
    return accounts


def _id(account: ServiceAccount) -> str:
    digest = hashlib.sha256(f"{account.account}|{account.spn}".encode()).hexdigest()[:12]
    return f"KRB-{digest.upper()}"


def score(account: ServiceAccount) -> tuple[int, list[str]]:
    points = 0
    rationale: list[str] = []
    if not account.enabled:
        return 0, ["Account is disabled; retain governance review but no active exposure score."]
    if account.encryption == "rc4":
        points += 30
        rationale.append("RC4 compatibility materially increases offline password-recovery exposure.")
    elif account.encryption == "unknown":
        points += 15
        rationale.append("Encryption posture is unknown and requires validation.")
    if account.password_age_days > 365:
        points += 20
        rationale.append("Password age exceeds 365 days.")
    elif account.password_age_days > 180:
        points += 12
        rationale.append("Password age exceeds 180 days.")
    if account.privileged:
        points += 20
        rationale.append("Service identity has privileged rights.")
    if account.interactive_logon:
        points += 10
        rationale.append("Interactive logon is permitted for a service identity.")
    if not account.managed_identity:
        points += 8
        rationale.append("Account is not managed by gMSA or equivalent rotation control.")
    points += CRITICALITY_WEIGHT[account.criticality]
    if account.criticality in {"high", "critical"}:
        rationale.append(f"Account supports a {account.criticality}-criticality service.")
    return min(points, 100), rationale


def severity(score_value: int) -> str:
    if score_value >= 80:
        return "critical"
    if score_value >= 60:
        return "high"
    if score_value >= 35:
        return "medium"
    return "low"


def assess(accounts: Iterable[ServiceAccount]) -> List[Finding]:
    findings: List[Finding] = []
    for account in accounts:
        risk, rationale = score(account)
        if risk == 0:
            continue
        remediation = ["Confirm business owner and service dependency before change."]
        if account.encryption in {"rc4", "unknown"}:
            remediation.append("Validate Kerberos encryption support and migrate to AES where compatible.")
        if account.password_age_days > 180 and not account.managed_identity:
            remediation.append("Rotate the credential through an approved change and evaluate gMSA adoption.")
        if account.privileged:
            remediation.append("Remove unnecessary privileged group membership and validate least privilege.")
        if account.interactive_logon:
            remediation.append("Deny interactive logon unless a documented exception is approved.")
        remediation.append("Re-run inventory and authentication telemetry validation after remediation.")
        findings.append(Finding(
            finding_id=_id(account), account=account.account,
            title="Kerberos service-account exposure",
            severity=severity(risk), score=risk,
            rationale=tuple(rationale),
            mitre_attack=("T1558.003 - Kerberoasting", "T1078 - Valid Accounts"),
            remediation=tuple(remediation),
        ))
    return sorted(findings, key=lambda item: (-item.score, item.account.lower()))


def metrics(findings: Iterable[Finding]) -> dict:
    items = list(findings)
    return {
        "findings": len(items),
        "critical": sum(x.severity == "critical" for x in items),
        "high": sum(x.severity == "high" for x in items),
        "medium": sum(x.severity == "medium" for x in items),
        "low": sum(x.severity == "low" for x in items),
        "average_score": round(sum(x.score for x in items) / len(items), 1) if items else 0.0,
    }
