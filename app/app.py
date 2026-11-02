#!/usr/bin/env python3
"""Local Sigma/Elastic detection-rule explorer. Python standard library only."""
from http.server import ThreadingHTTPServer, SimpleHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
from pathlib import Path
import json, os, threading

ROOT = Path(__file__).resolve().parent
RULES_DIR = Path(os.environ.get("SIGMA_RULES_DIR", ROOT / "rules" / "ndjson")).expanduser().resolve()
HOST = os.environ.get("HOST", "127.0.0.1")
PORT = int(os.environ.get("PORT", "8082"))

records = []
categories = {}
load_errors = 0
lock = threading.Lock()

def load_rules():
    global records, categories, load_errors
    loaded, cats, errors = [], {}, 0
    if not RULES_DIR.exists():
        raise SystemExit(f"Rules directory not found: {RULES_DIR}\nSet SIGMA_RULES_DIR to your rules/ndjson directory.")
    for path in sorted(RULES_DIR.rglob("*.ndjson")):
        category = str(path.relative_to(RULES_DIR).parent)
        try:
            with path.open("r", encoding="utf-8", errors="replace") as fh:
                for line_no, line in enumerate(fh, 1):
                    if not line.strip():
                        continue
                    try:
                        item = json.loads(line)
                        if not isinstance(item, dict):
                            errors += 1
                            continue
                        item["_category"] = category if category != "." else "uncategorized"
                        item["_source_file"] = str(path.relative_to(RULES_DIR))
                        item["_local_id"] = f"{path.relative_to(RULES_DIR)}:{line_no}"
                        loaded.append(item)
                        cats[item["_category"]] = cats.get(item["_category"], 0) + 1
                    except json.JSONDecodeError:
                        errors += 1
        except OSError:
            errors += 1
    records, categories, load_errors = loaded, cats, errors

def send_json(handler, payload, status=200):
    data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    handler.send_response(status)
    handler.send_header("Content-Type", "application/json; charset=utf-8")
    handler.send_header("Content-Length", str(len(data)))
    handler.send_header("Cache-Control", "no-store")
    handler.end_headers()
    handler.wfile.write(data)

class Handler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(ROOT), **kwargs)

    def log_message(self, fmt, *args):
        print("[http]", fmt % args)

    def do_GET(self):
        parsed = urlparse(self.path)
        params = parse_qs(parsed.query)
        if parsed.path == "/api/stats":
            severities = {}
            for r in records:
                s = str(r.get("severity") or "unknown").lower()
                severities[s] = severities.get(s, 0) + 1
            top = sorted(categories.items(), key=lambda x: x[1], reverse=True)[:12]
            send_json(self, {
                "total": len(records), "files": len(list(RULES_DIR.rglob("*.ndjson"))),
                "categories": len(categories), "errors": load_errors,
                "severity": severities,
                "top_categories": [{"name": k, "count": v} for k, v in top],
                "rule_dir": str(RULES_DIR)
            })
            return
        if parsed.path == "/api/categories":
            send_json(self, [{"name": k, "count": v} for k, v in sorted(categories.items())])
            return
        if parsed.path == "/api/rules":
            q = params.get("q", [""])[0].strip().lower()
            cat = params.get("category", [""])[0]
            sev = params.get("severity", [""])[0].lower()
            try:
                offset = max(0, int(params.get("offset", ["0"])[0]))
                limit = min(100, max(1, int(params.get("limit", ["25"])[0])))
            except ValueError:
                offset, limit = 0, 25
            found = []
            for r in records:
                if cat and r.get("_category") != cat:
                    continue
                if sev and str(r.get("severity", "")).lower() != sev:
                    continue
                if q:
                    hay = " ".join([
                        str(r.get("name", "")), str(r.get("description", "")),
                        str(r.get("tags", "")), str(r.get("threat", "")),
                        str(r.get("rule_id", "")), str(r.get("_category", ""))
                    ]).lower()
                    if q not in hay:
                        continue
                found.append(r)
            page = found[offset:offset+limit]
            fields = ("name", "description", "severity", "risk_score", "rule_id", "tags", "threat", "_category", "_source_file", "_local_id", "type", "language")
            send_json(self, {"total": len(found), "offset": offset, "limit": limit,
                             "items": [{k: r.get(k) for k in fields} for r in page]})
            return
        if parsed.path == "/api/rule":
            key = params.get("id", [""])[0]
            r = next((x for x in records if x.get("_local_id") == key), None)
            if r is None:
                send_json(self, {"error": "Rule not found"}, 404)
            else:
                send_json(self, r)
            return
        if parsed.path == "/":
            self.path = "/index.html"
        return super().do_GET()

if __name__ == "__main__":
    print(f"Loading Elastic NDJSON rules from: {RULES_DIR}")
    load_rules()
    print(f"Loaded {len(records):,} valid records across {len(categories):,} categories; parse errors: {load_errors}")
    print(f"Open http://{HOST}:{PORT}")
    ThreadingHTTPServer((HOST, PORT), Handler).serve_forever()
