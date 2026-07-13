import http.server
import json
import os
import urllib.parse
from pathlib import Path


class DashboardHTTPHandler(http.server.SimpleHTTPRequestHandler):
    scan_dir: Path = Path(".")
    template_path: Path = Path(".")

    def do_GET(self) -> None:
        parsed_url = urllib.parse.urlparse(self.path)
        path = parsed_url.path

        # API: list all scans
        if path == "/api/scans":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            try:
                scans = []
                for p in sorted(
                    self.scan_dir.glob("*.json"), key=os.path.getmtime, reverse=True
                ):
                    # Quick validate if it looks like a scan result JSON
                    try:
                        data = json.loads(p.read_text(encoding="utf-8"))
                        if isinstance(data, dict) and "target" in data:
                            scans.append(
                                {
                                    "filename": p.name,
                                    "target": data["target"].get("name", "unknown"),
                                    "overall_score": data.get("overall_score", 0.0),
                                    "grade": data.get("grade", "F"),
                                    "timestamp": data.get("started_at", ""),
                                    "total_findings": sum(
                                        len(m.get("findings", []))
                                        for m in data.get("modules", [])
                                    ),
                                }
                            )
                    except Exception:
                        continue
                self.wfile.write(json.dumps(scans).encode("utf-8"))
            except Exception as e:
                self.wfile.write(json.dumps({"error": str(e)}).encode("utf-8"))
            return

        # API: fetch single scan content
        if path.startswith("/api/scan/"):
            filename = path[len("/api/scan/") :]
            # Safe path traversal check
            target_file = (self.scan_dir / filename).resolve()
            if (
                not target_file.is_file()
                or not target_file.name.endswith(".json")
                or not target_file.is_relative_to(self.scan_dir.resolve())
            ):
                self.send_response(404)
                self.end_headers()
                return

            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(target_file.read_bytes())
            return

        # API: fetch watch logs
        if path == "/api/watch":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            watch_log = Path.home() / ".crucible" / "watch_log.jsonl"
            entries = []
            if watch_log.exists():
                try:
                    for line in watch_log.read_text(encoding="utf-8").splitlines():
                        if line.strip():
                            entries.append(json.loads(line))
                except Exception:
                    pass
            self.wfile.write(json.dumps(entries).encode("utf-8"))
            return

        # Serve Dashboard HTML (single-page app)
        if path == "/" or path == "/index.html":
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            if self.template_path.exists():
                self.wfile.write(self.template_path.read_bytes())
            else:
                self.wfile.write(b"<h1>Dashboard Template Not Found</h1>")
            return

        # Fallback to default handler for static files
        super().do_GET()


def start_dashboard(scan_dir: Path, host: str = "127.0.0.1", port: int = 8080) -> None:
    # Resolve paths
    current_dir = Path(__file__).parent
    template_path = current_dir / "templates" / "dashboard.html"

    # Set class variables for handler
    DashboardHTTPHandler.scan_dir = scan_dir
    DashboardHTTPHandler.template_path = template_path

    # Start server
    server = http.server.HTTPServer((host, port), DashboardHTTPHandler)
    server.serve_forever()
