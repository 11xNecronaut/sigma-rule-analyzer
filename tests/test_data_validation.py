
"""Unit tests for detection rule quality validation."""

import sys
import unittest
from pathlib import Path

APP_DIR = Path(__file__).resolve().parents[1] / "app"
sys.path.insert(0, str(APP_DIR))

from validation import validate_rule, validate_collection


class TestRuleValidation(unittest.TestCase):

    def setUp(self):

        self.valid_rule = {
            "rule_id": "test-001",
            "name": "Test PowerShell Detection",
            "description": "Detects suspicious PowerShell execution.",
            "type": "query",
            "language": "lucene",
            "query": "process.name: powershell.exe",
            "severity": "high",
            "risk_score": 70,
            "index": ["winlogbeat-*"],
            "tags": ["attack.execution"]
        }

    def test_valid_rule(self):
        self.assertEqual(
            validate_rule(self.valid_rule),
            []
        )

    def test_missing_rule_name(self):
        rule = self.valid_rule.copy()
        del rule["name"]

        results = validate_rule(rule)

        self.assertIn(
            "MISSING_NAME",
            [item["code"] for item in results]
        )

    def test_missing_description(self):
        rule = self.valid_rule.copy()
        del rule["description"]

        results = validate_rule(rule)

        self.assertIn(
            "MISSING_DESCRIPTION",
            [item["code"] for item in results]
        )

    def test_invalid_severity(self):
        rule = self.valid_rule.copy()
        rule["severity"] = "extreme"

        results = validate_rule(rule)

        self.assertIn(
            "INVALID_SEVERITY",
            [item["code"] for item in results]
        )

    def test_invalid_risk_score(self):
        rule = self.valid_rule.copy()
        rule["risk_score"] = 150

        results = validate_rule(rule)

        self.assertIn(
            "INVALID_RISK_SCORE",
            [item["code"] for item in results]
        )

    def test_missing_query_language(self):
        rule = self.valid_rule.copy()
        del rule["language"]

        results = validate_rule(rule)

        self.assertIn(
            "MISSING_LANGUAGE",
            [item["code"] for item in results]
        )

    def test_invalid_index_format(self):
        rule = self.valid_rule.copy()
        rule["index"] = "winlogbeat-*"

        results = validate_rule(rule)

        self.assertIn(
            "INVALID_INDEX",
            [item["code"] for item in results]
        )

    def test_invalid_record(self):
        results = validate_rule("not a JSON object")

        self.assertEqual(
            results[0]["code"],
            "INVALID_RECORD"
        )

    def test_duplicate_rule_ids(self):

        duplicate = self.valid_rule.copy()

        results = validate_collection([
            self.valid_rule,
            duplicate
        ])

        self.assertEqual(results["total_rules"], 2)
        self.assertEqual(results["invalid_rules"], 1)

        self.assertIn(
            "DUPLICATE_RULE_ID",
            [item["code"] for item in results["findings"]]
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
