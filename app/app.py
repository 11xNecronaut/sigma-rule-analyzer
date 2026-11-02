
#!/usr/bin/env python3
"""
Sigma Detection Intelligence
Local detection rule exploration and analysis.

Supports:
- Nested NDJSON directories
- Compressed NDJSON ZIP archives
- Rule search and filtering
- Severity and category statistics
"""

from http.server import ThreadingHTTPServer, SimpleHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
from pathlib import Path, PurePosixPath
from zipfile import ZipFile, BadZipFile
import json
import os
import threading

ROOT = Path(__file__).resolve().parent

# Prefer an explicitly supplied directory or archive.
if os.environ.get("SIGMA_RULES_DIR"):
    RULES_SOURCE = Path(os.environ["SIGMA_RULES_DIR"]).expanduser().resolve()
elif os.environ.get("SIGMA_RULES_SOURCE"):
    RULES_SOURCE = Path(os.environ["SIGMA_RULES_SOURCE"]).expanduser().resolve()
else:
    RULES_SOURCE = (ROOT.parent / "rules" / "ndjson.zip").resolve()

HOST = os.environ.get("HOST", "127.0.0.1")
PORT = int(os.environ.get("PORT", "8082"))

records = []
categories = {}
load_errors = 0
loaded_files = 0
lock = threading.Lock()


def normalize_archive_path(name):
    """Remove packaging directories from ZIP member paths."""
    parts = list(PurePosixPath(name).parts)

    if "ndjson" in parts:
        parts = parts[parts.index("ndjson") + 1:]

    return PurePosixPath(*parts).as_posix()


def process_lines(lines, relative_path, loaded, cats):
    """Parse NDJSON lines and add valid detection records."""
    errors = 0

    category = str(PurePosixPath(relative_path).parent)

    if category == ".":
        category = "uncategorized"

    for line_no, line in enumerate(lines, 1):
        if isinstance(line, bytes):
            line = line.decode("utf-8", errors="replace")

        if not line.strip():
            continue

        try:
            item = json.loads(line)

            if not isinstance(item, dict):
                errors += 1
                continue

            item["_category"] = category
            item["_source_file"] = relative_path
            item["_local_id"] = f"{relative_path}:{line_no}"

            loaded.append(item)
            cats[category] = cats.get(category, 0) + 1

        except json.JSONDecodeError:
            errors += 1

    return errors


def load_rules():
    """Load NDJSON records from a directory or ZIP archive."""
    global records, categories, load_errors, loaded_files

    loaded = []
    cats = {}
    errors = 0
    file_count = 0

    if RULES_SOURCE.is_dir():

        files = sorted(RULES_SOURCE.rglob("*.ndjson"))
        file_count = len(files)

        for path in files:
            relative_path = path.relative_to(RULES_SOURCE).as_posix()

            try:
                with path.open(
                    "r", encoding="utf-8", errors="replace"
                ) as file:
                    errors += process_lines(
                        file, relative_path, loaded, cats
                    )
            except OSError:
                errors += 1

    elif RULES_SOURCE.is_file() and RULES_SOURCE.suffix.lower() == ".zip":

        try:
            with ZipFile(RULES_SOURCE, "r") as archive:

                members = sorted(
                    name for name in archive.namelist()
                    if name.lower().endswith(".ndjson")
                    and not name.endswith("/")
                )

                file_count = len(members)

                for member in members:
                    relative_path = normalize_archive_path(member)

                    if not relative_path:
                        continue

                    try:
                        with archive.open(member) as file:
                            errors += process_lines(
                                file, relative_path, loaded, cats
                            )
                    except (OSError, RuntimeError):
                        errors += 1

        except BadZipFile:
            raise SystemExit(f"Invalid ZIP archive: {RULES_SOURCE}")

    else:
        raise SystemExit(
            f"Rule source not found: {RULES_SOURCE}\n"
            "Configure SIGMA_RULES_DIR or SIGMA_RULES_SOURCE."
        )

    with lock:
        records = loaded
        categories = cats
        load_errors = errors
        loaded_files = file_count

    print(
        f"[INFO] Loaded {len(records):,} valid records "
        f"from {loaded_files:,} files."
    )
    print(f"[INFO] Parsing errors: {load_errors}")


def send_json(handler, payload, status=200):
    """Send a JSON response."""
    data = json.dumps(payload, ensure_ascii=False).encode("utf-8")

    handler.send_response(status)
    handler.send_header(
        "Content-Type", "application/json; charset=utf-8"
    )
    handler.send_header("Content-Length", str(len(data)))
    handler.send_header("Cache-Control", "no-store")
    handler.end_headers()
    handler.wfile.write(data)


class Handler(SimpleHTTPRequestHandler):

    def __init__(self, *args, **kwargs):
        super().__init__(
            *args, directory=str(ROOT), **kwargs
        )

    def log_message(self, fmt, *args):
        print("[HTTP]", fmt % args)

    def do_GET(self):
        parsed = urlparse(self.path)
        params = parse_qs(parsed.query)

        # Overall statistics
        if parsed.path == "/api/stats":

            severities = {}

            for rule in records:
                severity = str(
                    rule.get("severity") or "unknown"
                ).lower()

                severities[severity] = (
                    severities.get(severity, 0) + 1
                )

            top = sorted(
                categories.items(),
                key=lambda item: item[1],
                reverse=True
            )[:12]

            send_json(self, {
                "total": len(records),
                "files": loaded_files,
                "categories": len(categories),
                "errors": load_errors,
                "severity": severities,
                "top_categories": [
                    {"name": name, "count": count}
                    for name, count in top
                ],
                "rule_source": str(RULES_SOURCE)
            })
            return

        # Available categories
        if parsed.path == "/api/categories":

            result = [
                {"name": name, "count": count}
                for name, count in sorted(categories.items())
            ]

            send_json(self, result)
            return

        # Search and filter rules
        if parsed.path == "/api/rules":

            query = params.get("q", [""])[0].strip().lower()
            category = params.get("category", [""])[0]
            severity = params.get("severity", [""])[0].lower()

            try:
                offset = max(
                    0, int(params.get("offset", ["0"])[0])
                )
                limit = min(
                    100,
                    max(1, int(params.get("limit", ["25"])[0]))
                )
            except ValueError:
                offset, limit = 0, 25

            found = []

            for rule in records:

                if category and rule.get("_category") != category:
                    continue

                if severity and str(
                    rule.get("severity", "")
                ).lower() != severity:
                    continue

                if query:
                    searchable = " ".join([
                        str(rule.get("name", "")),
                        str(rule.get("description", "")),
                        str(rule.get("query", "")),
                        str(rule.get("tags", "")),
                        str(rule.get("threat", "")),
                        str(rule.get("rule_id", "")),
                        str(rule.get("_category", ""))
                    ]).lower()

                    if query not in searchable:
                        continue

                found.append(rule)

            page = found[offset:offset + limit]

            fields = (
                "name",
                "description",
                "severity",
                "risk_score",
                "rule_id",
                "tags",
                "threat",
                "_category",
                "_source_file",
                "_local_id",
                "type",
                "language"
            )

            send_json(self, {
                "total": len(found),
                "offset": offset,
                "limit": limit,
                "items": [
                    {key: rule.get(key) for key in fields}
                    for rule in page
                ]
            })
            return

        # Individual rule details
        if parsed.path == "/api/rule":

            requested_id = params.get("id", [""])[0]

            rule = next(
                (
                    item for item in records
                    if item.get("_local_id") == requested_id
                ),
                None
            )

            if rule is None:
                send_json(
                    self, {"error": "Rule not found"}, 404
                )
            else:
                send_json(self, rule)

            return

        # Main application interface
        if parsed.path == "/":
            self.path = "/index.html"

        return super().do_GET()


if __name__ == "__main__":

    print("=" * 55)
    print("       SIGMA DETECTION INTELLIGENCE")
    print("=" * 55)

    print(f"[INFO] Rule source: {RULES_SOURCE}")

    load_rules()

    print(f"[INFO] Server: http://{HOST}:{PORT}")
    print("[INFO] Press CTRL+C to stop.")

    ThreadingHTTPServer(
        (HOST, PORT), Handler
    ).serve_forever()
