from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Tuple

ALLOWED_CRITICALITY = {"low", "medium", "high", "critical"}
ALLOWED_ENCRYPTION = {"aes256", "aes128", "rc4", "unknown"}


@dataclass(frozen=True)
class ServiceAccount:
    account: str
    spn: str
    owner: str
    criticality: str
    encryption: str
    password_age_days: int
    privileged: bool
    interactive_logon: bool
    managed_identity: bool
    enabled: bool
    last_reviewed: str

    def validate(self) -> None:
        if not self.account or not self.spn or not self.owner:
            raise ValueError("account, spn and owner are required")
        if self.criticality not in ALLOWED_CRITICALITY:
            raise ValueError(f"unsupported criticality: {self.criticality}")
        if self.encryption not in ALLOWED_ENCRYPTION:
            raise ValueError(f"unsupported encryption: {self.encryption}")
        if self.password_age_days < 0:
            raise ValueError("password_age_days cannot be negative")
        try:
            reviewed = datetime.fromisoformat(self.last_reviewed.replace("Z", "+00:00"))
        except ValueError as exc:
            raise ValueError("last_reviewed must be ISO-8601") from exc
        if reviewed.tzinfo is None:
            raise ValueError("last_reviewed must include timezone")
        if reviewed > datetime.now(timezone.utc):
            raise ValueError("last_reviewed cannot be in the future")


@dataclass(frozen=True)
class Finding:
    finding_id: str
    account: str
    title: str
    severity: str
    score: int
    rationale: Tuple[str, ...]
    mitre_attack: Tuple[str, ...]
    remediation: Tuple[str, ...]
