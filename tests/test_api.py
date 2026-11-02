
"""
API tests for Sigma Detection Intelligence.

Tests:
- Statistics endpoint
- Category endpoint
- Rule search
- Severity and category filtering
- Individual rule retrieval
- Invalid rule handling
"""

import json
import sys
import tempfile
import threading
import unittest

from pathlib import Path
from urllib.error import HTTPError
from urllib.parse import urlencode
from urllib.request import urlopen
from zipfile import ZipFile
from http.server import ThreadingHTTPServer

APP_DIR = Path(__file__).resolve().parents[1] / "app"
sys.path.insert(0, str(APP_DIR))

import app as application


class TestDetectionAPI(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.temp_dir = tempfile.TemporaryDirectory()
        cls.root = Path(cls.temp_dir.name)
        cls.archive = cls.root / "test_rules.zip"

        cls.rules = [
            {
                "rule_id": "api-test-001",
                "name": "Suspicious PowerShell Execution",
                "description": "Detects encoded PowerShell commands",
                "severity": "high",
                "risk_score": 70,
                "query": "process.name: powershell.exe",
                "tags": ["attack.execution"],
                "threat": []
            },
            {
                "rule_id": "api-test-002",
                "name": "Linux Authentication Activity",
                "description": "Detects authentication activity",
                "severity": "medium",
                "risk_score": 40,
                "query": "event.category: authentication",
                "tags": ["linux"],
                "threat": []
            }
        ]

        with ZipFile(cls.archive, "w") as archive:

            archive.writestr(
                "rules/ndjson/application/antivirus/rules.ndjson",
                json.dumps(cls.rules[0]) + "\n"
            )

            archive.writestr(
                "rules/ndjson/linux/authentication/rules.ndjson",
                json.dumps(cls.rules[1]) + "\n"
            )

        cls.original_source = application.RULES_SOURCE
        application.RULES_SOURCE = cls.archive

        application.load_rules()

        cls.server = ThreadingHTTPServer(
            ("127.0.0.1", 0),
            application.Handler
        )

        cls.port = cls.server.server_address[1]

        cls.thread = threading.Thread(
            target=cls.server.serve_forever,
            daemon=True
        )
        cls.thread.start()

        cls.base_url = f"http://127.0.0.1:{cls.port}"

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join()

        application.RULES_SOURCE = cls.original_source
        cls.temp_dir.cleanup()

    def get_json(self, endpoint, params=None):

        url = self.base_url + endpoint

        if params:
            url += "?" + urlencode(params)

        with urlopen(url, timeout=5) as response:
            self.assertEqual(response.status, 200)
            return json.loads(response.read().decode("utf-8"))

    def test_stats_endpoint(self):

        result = self.get_json("/api/stats")

        self.assertEqual(result["total"], 2)
        self.assertEqual(result["files"], 2)
        self.assertEqual(result["categories"], 2)

    def test_categories_endpoint(self):

        result = self.get_json("/api/categories")

        category_names = [
            item["name"] for item in result
        ]

        self.assertIn("application/antivirus", category_names)
        self.assertIn("linux/authentication", category_names)

    def test_power_shell_search(self):

        result = self.get_json(
            "/api/rules",
            {"q": "PowerShell"}
        )

        self.assertEqual(result["total"], 1)

        self.assertIn(
            "PowerShell",
            result["items"][0]["name"]
        )

    def test_severity_filter(self):

        result = self.get_json(
            "/api/rules",
            {"severity": "high"}
        )

        self.assertEqual(result["total"], 1)
        self.assertEqual(
            result["items"][0]["severity"],
            "high"
        )

    def test_category_filter(self):

        result = self.get_json(
            "/api/rules",
            {"category": "linux/authentication"}
        )

        self.assertEqual(result["total"], 1)

        self.assertEqual(
            result["items"][0]["name"],
            "Linux Authentication Activity"
        )

    def test_individual_rule_retrieval(self):

        result = self.get_json(
            "/api/rule",
            {"id": application.records[0]["_local_id"]}
        )

        self.assertIn("rule_id", result)
        self.assertIn("_local_id", result)

    def test_nonexistent_rule(self):

        with self.assertRaises(HTTPError) as error:

            self.get_json(
                "/api/rule",
                {"id": "nonexistent-rule"}
            )

        self.assertEqual(error.exception.code, 404)


if __name__ == "__main__":
    unittest.main(verbosity=2)
