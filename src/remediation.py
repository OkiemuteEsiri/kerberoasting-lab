from dataclasses import dataclass


@dataclass(frozen=True)
class ClosureEvidence:
    change_reference: str
    owner_approval: bool
    password_rotated: bool
    aes_validated: bool
    privilege_reviewed: bool
    interactive_logon_reviewed: bool
    post_change_authentication_validated: bool


def validate_closure(evidence: ClosureEvidence) -> tuple[str, tuple[str, ...]]:
    missing = []
    if not evidence.change_reference.strip():
        missing.append("change reference")
    if not evidence.owner_approval:
        missing.append("owner approval")
    if not evidence.password_rotated:
        missing.append("credential rotation evidence")
    if not evidence.aes_validated:
        missing.append("AES compatibility/usage validation")
    if not evidence.privilege_reviewed:
        missing.append("privilege review")
    if not evidence.interactive_logon_reviewed:
        missing.append("interactive-logon review")
    if not evidence.post_change_authentication_validated:
        missing.append("post-change authentication validation")
    if missing:
        return "needs_evidence", tuple(missing)
    return "validated", ()
