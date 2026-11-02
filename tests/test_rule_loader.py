
"""
Unit tests for Sigma Detection Intelligence rule ingestion.

Tests:
- Nested NDJSON archive ingestion
- JSON record parsing
- Category extraction
- Malformed record handling
- Invalid archive handling
"""

import json
import sys
import tempfile
import unittest

from pathlib import Path
from zipfile import ZipFile

# Import the application backend
APP_DIR = Path(__file__).resolve().parents[1] / "app"
sys.path.insert(0, str(APP_DIR))

import app as application


class TestRuleLoader(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.root = Path(self.temp_dir.name)
        self.archive = self.root / "ndjson.zip"

        self.valid_rule_1 = {
            "rule_id": "test-rule-001",
            "name": "Test Antivirus Detection",
            "description": "Example antivirus detection rule",
            "severity": "high",
            "risk_score": 70,
            "query": "process.name: test.exe",
            "tags": ["test", "attack.execution"]
        }

        self.valid_rule_2 = {
            "rule_id": "test-rule-002",
            "name": "Test Linux Authentication Detection",
            "description": "Example Linux authentication rule",
            "severity": "medium",
            "risk_score": 45,
            "query": "event.category: authentication",
            "tags": ["linux", "authentication"]
        }

        with ZipFile(self.archive, "w") as archive:

            archive.writestr(
                "rules/ndjson/application/antivirus/test.ndjson",
                json.dumps(self.valid_rule_1) + "\n"
            )

            archive.writestr(
                "rules/ndjson/linux/authentication/test.ndjson",
                json.dumps(self.valid_rule_2)
                + "\n"
                + "{invalid json}\n"
            )

        self.original_source = application.RULES_SOURCE
        application.RULES_SOURCE = self.archive

        application.load_rules()

    def tearDown(self):
        application.RULES_SOURCE = self.original_source
        self.temp_dir.cleanup()

    def test_valid_records_are_loaded(self):
        """Verify that valid JSON records are loaded."""

        self.assertEqual(len(application.records), 2)

    def test_archive_file_count(self):
        """Verify the number of NDJSON files discovered."""

        self.assertEqual(application.loaded_files, 2)

    def test_nested_categories_are_extracted(self):
        """Verify category paths are preserved."""

        self.assertIn(
            "application/antivirus",
            application.categories
        )

        self.assertIn(
            "linux/authentication",
            application.categories
        )

    def test_rule_metadata_is_preserved(self):
        """Verify important rule fields survive parsing."""

        rule = next(
            record for record in application.records
            if record.get("rule_id") == "test-rule-001"
        )

        self.assertEqual(
            rule["name"],
            "Test Antivirus Detection"
        )

        self.assertEqual(rule["severity"], "high")
        self.assertEqual(rule["risk_score"], 70)

    def test_malformed_json_is_counted(self):
        """Verify malformed records are recorded as errors."""

        self.assertEqual(application.load_errors, 1)

    def test_local_identifiers_are_unique(self):
        """Verify individual records have distinct identifiers."""

        identifiers = [
            record["_local_id"]
            for record in application.records
        ]

        self.assertEqual(
            len(identifiers),
            len(set(identifiers))
        )

    def test_zip_source_is_preserved(self):
        """Verify source paths retain nested directory information."""

        paths = [
            record["_source_file"]
            for record in application.records
        ]

        self.assertTrue(
            any("application/antivirus" in path for path in paths)
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
