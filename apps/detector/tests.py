from django.test import SimpleTestCase
from django.core.files.uploadedfile import SimpleUploadedFile
import os
from tempfile import TemporaryDirectory

from apps.detector.services.analysis import compute_scores
from apps.detector.services.parser import parse_email
from apps.detector.serializers import ScanRequestSerializer
from apps.detector.services.report import generate_pdf
from apps.detector.services.ai_service import _apply_risk_guardrails
from apps.detector.services.rules import evaluate_rules
from apps.detector.services.privacy import mask_sensitive_text


class DetectorScoringTests(SimpleTestCase):
    def test_compute_scores_ai_only(self):
        parsed = {"spf": "pass", "dkim": "pass", "dmarc": "pass"}
        reputation = {"urls": {}, "domains": {}, "ips": {}}

        ai_out = {"confidence": 100, "is_phishing": True}
        scores = compute_scores(parsed, reputation, ai_out)
        self.assertEqual(scores["final_score"], 100.0)
        self.assertEqual(scores["malicious_ratio"], 0.0)
        self.assertEqual(scores["header_score"], 0.0)

        # Benign with high confidence must not inflate the risk score,
        # but should not collapse to zero on every request either.
        ai_out_benign = {"confidence": 95, "is_phishing": False}
        scores = compute_scores(parsed, reputation, ai_out_benign)
        self.assertEqual(scores["final_score"], 5.0)
        self.assertEqual(scores["malicious_ratio"], 0.0)
        self.assertEqual(scores["header_score"], 0.0)

    def test_compute_scores_with_malicious_and_anomalies(self):
        parsed = {"spf": "fail", "dkim": "pass", "dmarc": "neutral"}
        reputation = {
            "urls": {
                "http://bad": {
                    "virustotal": {
                        "data": {
                            "attributes": {
                                "last_analysis_stats": {
                                    "malicious": 1,
                                }
                            }
                        }
                    }
                }
            },
            "domains": {},
            "ips": {},
        }
        ai_out = {"confidence": 80, "is_phishing": True}
        scores = compute_scores(parsed, reputation, ai_out)

        self.assertEqual(scores["header_score"], round((2 / 3) * 100, 2))
        self.assertEqual(scores["malicious_ratio"], 1.0)
        self.assertGreaterEqual(scores["final_score"], 80.0)
        self.assertGreaterEqual(scores["final_score"], 80.0)

    def test_compute_scores_benign_but_structurally_suspicious_email(self):
        parsed = {
            "headers": {
                "From": "Freddy Greer <bGreer@msbx.net>",
            },
            "spf": None,
            "dkim": None,
            "dmarc": None,
            "urls": ["http://lool.hk"],
            "domains": ["lool.hk"],
        }
        reputation = {"urls": {}, "domains": {}, "ips": {}}
        ai_out = {"confidence": 30, "is_phishing": False}

        scores = compute_scores(parsed, reputation, ai_out)

        self.assertEqual(scores["header_score"], 100.0)
        self.assertGreaterEqual(scores["final_score"], 50.0)

    def test_compute_scores_url_only_input_keeps_nonzero_risk(self):
        parsed = {
            "headers": {},
            "spf": None,
            "dkim": None,
            "dmarc": None,
            "urls": ["http://example.test"],
            "domains": ["example.test"],
        }
        reputation = {"urls": {}, "domains": {}, "ips": {}}
        ai_out = {"confidence": 30, "is_phishing": False}

        scores = compute_scores(parsed, reputation, ai_out)
        self.assertGreater(scores["final_score"], 0.0)

    def test_compute_scores_inconsistent_malware_type_not_low(self):
        parsed = {
            "headers": {
                "From": '"Goodrich, Aurelia" <Dahl1U@compubase-europe.com>',
                "Subject": "<iframe onload=alert(/a/);>",
            },
            "spf": None,
            "dkim": None,
            "dmarc": None,
            "urls": [],
            "domains": [],
        }
        reputation = {"urls": {}, "domains": {}, "ips": {}}
        ai_out = {"confidence": 35, "is_phishing": False, "attack_type": "malware"}

        scores = compute_scores(parsed, reputation, ai_out)
        self.assertEqual(scores["header_score"], 100.0)
        self.assertGreaterEqual(scores["final_score"], 60.0)


class DetectorAIGuardrailTests(SimpleTestCase):
    def test_guardrail_escalates_suspicious_subject_with_auth_anomalies(self):
        parsed = {
            "headers": {
                "From": '"Goodrich, Aurelia" <Dahl1U@compubase-europe.com>',
                "Subject": "<iframe onload=alert(/a/);>",
            },
            "spf": None,
            "dkim": None,
            "dmarc": None,
            "urls": [],
            "domains": [],
        }

        guarded = _apply_risk_guardrails(
            parsed=parsed,
            is_phishing=False,
            confidence=35,
            attack_type="malware",
            signals=["missing SPF", "missing DKIM", "missing DMARC", "suspicious subject line"],
            reasoning="base",
        )

        self.assertTrue(guarded["is_phishing"])
        self.assertGreaterEqual(guarded["confidence"], 70)


class DetectorParserTests(SimpleTestCase):
    def test_parse_email_extracts_full_iocs(self):
        text = (
            "Visit https://example-site.com/a-b?x=1 "
            "and email test.user+1@example.org ip 192.168.1.10"
        )
        parsed = parse_email(text)

        self.assertIn("https://example-site.com/a-b?x=1", parsed["urls"])
        self.assertIn("test.user+1@example.org", parsed["emails"])
        self.assertIn("192.168.1.10", parsed["ips"])
        self.assertIn("example-site.com", parsed["domains"])


class DetectorScanRequestSerializerTests(SimpleTestCase):
    def test_eml_file_is_allowed_for_file_input_type(self):
        uploaded_file = SimpleUploadedFile(
            "sample.eml",
            b"From: alice@example.com\nTo: bob@example.com\nSubject: Hello\n\nBody",
            content_type="message/rfc822",
        )

        serializer = ScanRequestSerializer(data={"input_type": "file", "file": uploaded_file})
        self.assertTrue(serializer.is_valid(), serializer.errors)


class DetectorReportTests(SimpleTestCase):
    def test_generate_pdf_with_unicode_content(self):
        report = {
            "title": "Email Analysis Report",
            "summary": "Тест unicode summary",
            "ai": {"reasoning": "Причина: подозрительная ссылка"},
            "scoring": {"final_score": 77.5},
            "parsed": {"plain": "Пример текста с кириллицей"},
            "reputation": {"domains": {"пример.рф": {"note": "ok"}}},
        }

        with TemporaryDirectory() as temp_dir:
            out_path = os.path.join(temp_dir, "report.pdf")
            generated_path = generate_pdf(report, out_path)
            self.assertTrue(os.path.exists(generated_path))


class DetectorRuleTests(SimpleTestCase):
    def test_subject_rule_triggers(self):
        parsed = {
            "headers": {"Subject": "Urgent invoice requires attention"},
            "spf": "pass",
            "dkim": "pass",
            "dmarc": "pass",
            "urls": [],
            "domains": [],
        }
        result = evaluate_rules(parsed)
        self.assertGreater(result["score"], 0)
        self.assertTrue(any(r["id"] == "subject_urgent_language" for r in result["triggered"]))


class DetectorPrivacyTests(SimpleTestCase):
    def test_mask_sensitive_text(self):
        text = "Contact john.doe@example.com at https://example.com/path?x=1 ip 192.168.1.10"
        masked = mask_sensitive_text(text)
        self.assertIn("***@example.com", masked)
        self.assertIn("https://example.com/...", masked)
        self.assertIn("192.168.x.x", masked)
