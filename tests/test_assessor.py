import json
import tempfile
import unittest
from pathlib import Path

from src.assessor import assess, load_accounts, metrics, score, severity
from src.models import ServiceAccount
from src.remediation import ClosureEvidence, validate_closure
from src.report import render


def account(**overrides):
    base = dict(
        account="svc_demo",
        spn="HTTP/demo.corp.example",
        owner="Platform",
        criticality="high",
        encryption="aes256",
        password_age_days=30,
        privileged=False,
        interactive_logon=False,
        managed_identity=True,
        enabled=True,
        last_reviewed="2026-09-01T10:00:00+00:00",
    )
    base.update(overrides)
    return ServiceAccount(**base)


class AssessorTests(unittest.TestCase):
    def test_secure_managed_account_is_low(self):
        value, reasons = score(account())
        self.assertLess(value, 35)
        self.assertEqual(severity(value), "low")
        self.assertTrue(reasons)

    def test_rc4_old_privileged_account_is_critical(self):
        value, _ = score(account(encryption="rc4", password_age_days=800, privileged=True, interactive_logon=True, managed_identity=False, criticality="critical"))
        self.assertEqual(value, 100)
        self.assertEqual(severity(value), "critical")

    def test_disabled_account_scores_zero(self):
        self.assertEqual(score(account(enabled=False))[0], 0)

    def test_score_is_bounded(self):
        value, _ = score(account(encryption="rc4", password_age_days=9999, privileged=True, interactive_logon=True, managed_identity=False, criticality="critical"))
        self.assertLessEqual(value, 100)

    def test_deterministic_finding_id(self):
        first = assess([account()])[0].finding_id
        second = assess([account()])[0].finding_id
        self.assertEqual(first, second)

    def test_prioritization_orders_highest_first(self):
        findings = assess([account(account="a"), account(account="b", encryption="rc4", privileged=True, managed_identity=False)])
        self.assertGreaterEqual(findings[0].score, findings[1].score)

    def test_metrics(self):
        m = metrics(assess([account(), account(account="risk", encryption="rc4", privileged=True, managed_identity=False)]))
        self.assertEqual(m["findings"], 2)
        self.assertGreater(m["average_score"], 0)

    def test_report_contains_attack_context(self):
        text = render(assess([account(encryption="rc4")]))
        self.assertIn("T1558.003", text)
        self.assertIn("Remediation", text)

    def test_duplicate_records_rejected(self):
        row = {
            "account":"svc","spn":"HTTP/x","owner":"x","criticality":"high","encryption":"aes256",
            "password_age_days":1,"privileged":False,"interactive_logon":False,"managed_identity":True,"enabled":True,
            "last_reviewed":"2026-09-01T00:00:00+00:00"
        }
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "x.json"
            p.write_text(json.dumps([row, row]), encoding="utf-8")
            with self.assertRaises(ValueError):
                load_accounts(str(p))

    def test_missing_field_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "x.json"
            p.write_text(json.dumps([{"account":"svc"}]), encoding="utf-8")
            with self.assertRaises(ValueError):
                load_accounts(str(p))

    def test_invalid_encryption_rejected(self):
        with self.assertRaises(ValueError):
            account(encryption="des").validate()

    def test_complete_closure_evidence_validates(self):
        evidence = ClosureEvidence("CHG-1001", True, True, True, True, True, True)
        self.assertEqual(validate_closure(evidence)[0], "validated")

    def test_incomplete_closure_requires_evidence(self):
        evidence = ClosureEvidence("", False, False, False, False, False, False)
        state, missing = validate_closure(evidence)
        self.assertEqual(state, "needs_evidence")
        self.assertGreater(len(missing), 3)


if __name__ == "__main__":
    unittest.main()
