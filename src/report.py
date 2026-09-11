from .assessor import metrics


def render(findings) -> str:
    findings = list(findings)
    m = metrics(findings)
    lines = [
        "# Kerberos Service-Account Exposure Assessment",
        "",
        "> Synthetic, defensive assessment output. No ticket requests, password cracking, or live targeting are performed.",
        "",
        "## Executive summary",
        "",
        f"- Findings: **{m['findings']}**",
        f"- Critical: **{m['critical']}** | High: **{m['high']}** | Medium: **{m['medium']}** | Low: **{m['low']}**",
        f"- Average contextual score: **{m['average_score']} / 100**",
        "",
        "## Prioritized findings",
        "",
        "| ID | Account | Severity | Score |",
        "|---|---|---:|---:|",
    ]
    for finding in findings:
        lines.append(f"| {finding.finding_id} | `{finding.account}` | {finding.severity} | {finding.score} |")
    for finding in findings:
        lines.extend(["", f"## {finding.finding_id} — {finding.account}", "", "**Risk drivers**"])
        lines.extend(f"- {item}" for item in finding.rationale)
        lines.extend(["", "**MITRE ATT&CK context**"])
        lines.extend(f"- {item}" for item in finding.mitre_attack)
        lines.extend(["", "**Remediation and validation**"])
        lines.extend(f"- {item}" for item in finding.remediation)
    return "\n".join(lines) + "\n"
