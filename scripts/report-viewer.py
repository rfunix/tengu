#!/usr/bin/env python3
"""Tengu Report Viewer — serves pentest reports as styled HTML.

Usage:
    python3 report-viewer.py [--port 8888] [--dir /app/output]

Reads Markdown reports from the output directory and serves them as
professional HTML using the same CSS as Tengu's generate_report tool.
"""
from __future__ import annotations

import argparse
import html as html_module
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from urllib.parse import unquote

try:
    import markdown as md  # type: ignore[import-untyped]

    HAS_MARKDOWN = True
except ImportError:
    HAS_MARKDOWN = False

# CSS identical to src/tengu/tools/reporting/generate.py:316-356
_CSS = """\
:root {
  --critical: #dc2626;
  --high: #ea580c;
  --medium: #ca8a04;
  --low: #16a34a;
  --info: #2563eb;
}
body {
  font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
  max-width: 1100px;
  margin: 0 auto;
  padding: 2rem;
  color: #1a1a1a;
  line-height: 1.6;
}
h1 { color: #0f172a; border-bottom: 3px solid #dc2626; padding-bottom: 0.5rem; }
h2 { color: #0f172a; border-bottom: 1px solid #e2e8f0; padding-bottom: 0.3rem; margin-top: 2rem; }
h3 { color: #1e293b; }
table { border-collapse: collapse; width: 100%; margin: 1rem 0; }
th { background: #0f172a; color: white; padding: 0.5rem 1rem; text-align: left; }
td { padding: 0.5rem 1rem; border-bottom: 1px solid #e2e8f0; }
tr:nth-child(even) { background: #f8fafc; }
code { background: #f1f5f9; padding: 0.2rem 0.4rem; border-radius: 3px; font-size: 0.9em; }
pre { background: #1e293b; color: #e2e8f0; padding: 1rem; border-radius: 6px; overflow-x: auto; }
pre code { background: none; color: inherit; padding: 0; }
blockquote { border-left: 4px solid #dc2626; padding: 0.5rem 1rem; margin: 0; background: #fef2f2; }
.confidential {
  background: #fef2f2;
  border: 2px solid #dc2626;
  padding: 0.5rem 1rem;
  text-align: center;
  font-weight: bold;
  color: #dc2626;
  margin-bottom: 2rem;
}
@media print {
  body { max-width: none; }
  h1, h2, h3 { page-break-after: avoid; }
  table { page-break-inside: avoid; }
  .toolbar { display: none; }
}"""

_INDEX_EXTRA_CSS = """\
.report-list { list-style: none; padding: 0; }
.report-item {
  display: flex; align-items: center; justify-content: space-between;
  padding: 1rem 1.2rem; border: 1px solid #e2e8f0; border-radius: 8px;
  margin-bottom: 0.75rem; transition: box-shadow 0.15s;
}
.report-item:hover { box-shadow: 0 2px 8px rgba(0,0,0,0.08); }
.report-name { font-weight: 600; color: #0f172a; text-decoration: none; font-size: 1.05em; }
.report-name:hover { color: #dc2626; }
.report-meta { color: #64748b; font-size: 0.85em; }
.report-actions a {
  display: inline-block; padding: 0.3rem 0.8rem; border-radius: 4px;
  text-decoration: none; font-size: 0.85em; margin-left: 0.5rem;
}
.btn-view { background: #0f172a; color: white; }
.btn-view:hover { background: #1e293b; }
.btn-raw { background: #f1f5f9; color: #0f172a; }
.btn-raw:hover { background: #e2e8f0; }
.empty { text-align: center; color: #64748b; padding: 3rem 0; }"""

_TOOLBAR_CSS = """\
.toolbar {
  display: flex; gap: 1rem; align-items: center;
  padding: 0.75rem 0; margin-bottom: 1rem; border-bottom: 1px solid #e2e8f0;
}
.toolbar a, .toolbar button {
  display: inline-block; padding: 0.4rem 0.8rem; border-radius: 4px;
  text-decoration: none; font-size: 0.85em; cursor: pointer; border: none;
}
.toolbar a { background: #f1f5f9; color: #0f172a; }
.toolbar a:hover { background: #e2e8f0; }
.toolbar button { background: #0f172a; color: white; }
.toolbar button:hover { background: #1e293b; }"""


def _format_size(size: int) -> str:
    if size < 1024:
        return f"{size} B"
    if size < 1024 * 1024:
        return f"{size / 1024:.1f} KB"
    return f"{size / (1024 * 1024):.1f} MB"


def _format_time(ts: float) -> str:
    return time.strftime("%Y-%m-%d %H:%M", time.localtime(ts))


def _md_to_html(content: str, title: str) -> str:
    if HAS_MARKDOWN:
        body = md.markdown(
            content,
            extensions=["tables", "fenced_code", "toc", "attr_list"],
        )
    else:
        body = f"<pre>{html_module.escape(content)}</pre>"
    return body, title


def _render_page(title: str, body: str, extra_css: str = "") -> str:
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>{html_module.escape(title)}</title>
<style>{_CSS}
{extra_css}</style>
</head>
<body>
{body}
</body>
</html>"""


def _render_index(report_dir: Path) -> str:
    reports = sorted(report_dir.glob("*.md"), key=lambda p: p.stat().st_mtime, reverse=True)

    if not reports:
        items = '<div class="empty"><h2>No reports found</h2><p>Run a pentest first to generate reports.</p></div>'
    else:
        lines = []
        for r in reports:
            stat = r.stat()
            name = r.name
            size = _format_size(stat.st_size)
            mtime = _format_time(stat.st_mtime)
            lines.append(
                f'<li class="report-item">'
                f'<div><a class="report-name" href="/view/{html_module.escape(name)}">{html_module.escape(name)}</a>'
                f'<div class="report-meta">{size} &middot; {mtime}</div></div>'
                f'<div class="report-actions">'
                f'<a class="btn-view" href="/view/{html_module.escape(name)}">View</a>'
                f'<a class="btn-raw" href="/raw/{html_module.escape(name)}">Download .md</a>'
                f"</div></li>"
            )
        items = f'<ul class="report-list">{"".join(lines)}</ul>'

    body = f"<h1>Tengu Report Viewer</h1><p>{len(reports)} report(s) found</p>{items}"
    return _render_page("Tengu Report Viewer", body, _INDEX_EXTRA_CSS)


def _render_report(report_dir: Path, filename: str) -> str | None:
    safe_name = Path(filename).name
    if not safe_name.endswith(".md"):
        return None
    filepath = report_dir / safe_name
    if not filepath.is_file():
        return None

    content = filepath.read_text(encoding="utf-8")
    html_body, _ = _md_to_html(content, safe_name)

    toolbar = (
        '<div class="toolbar">'
        '<a href="/">&larr; Back to index</a>'
        f'<a href="/raw/{html_module.escape(safe_name)}">Download .md</a>'
        '<button onclick="window.print()">Print / Save PDF</button>'
        "</div>"
    )

    body = (
        f'<div class="confidential">CONFIDENTIAL — FOR AUTHORIZED RECIPIENTS ONLY</div>'
        f"{toolbar}{html_body}"
    )
    return _render_page(f"{safe_name} — Pentest Report", body, _TOOLBAR_CSS)


class ReportHandler(BaseHTTPRequestHandler):
    report_dir: Path

    def do_GET(self) -> None:  # noqa: N802
        path = unquote(self.path)

        if path in ("/", "/index"):
            self._send_html(_render_index(self.report_dir))

        elif path.startswith("/view/"):
            filename = path[6:]
            html_content = _render_report(self.report_dir, filename)
            if html_content is None:
                self._send_error(404, "Report not found")
            else:
                self._send_html(html_content)

        elif path.startswith("/raw/"):
            filename = Path(path[5:]).name
            if not filename.endswith(".md"):
                self._send_error(400, "Only .md files")
                return
            filepath = self.report_dir / filename
            if not filepath.is_file():
                self._send_error(404, "Report not found")
                return
            content = filepath.read_bytes()
            self.send_response(200)
            self.send_header("Content-Type", "text/markdown; charset=utf-8")
            self.send_header(
                "Content-Disposition", f'attachment; filename="{filename}"'
            )
            self.send_header("Content-Length", str(len(content)))
            self.end_headers()
            self.wfile.write(content)

        else:
            self._send_error(404, "Not found")

    def _send_html(self, content: str) -> None:
        encoded = content.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def _send_error(self, code: int, message: str) -> None:
        body = _render_page(
            f"Error {code}",
            f'<h1>Error {code}</h1><p>{html_module.escape(message)}</p><p><a href="/">Back to index</a></p>',
        )
        encoded = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def log_message(self, format: str, *args: object) -> None:  # noqa: A002
        print(f"[report-viewer] {args[0]} {args[1]}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Tengu Report Viewer")
    parser.add_argument("--port", type=int, default=8888, help="Port to listen on")
    parser.add_argument("--dir", type=str, default="/app/output", help="Report directory")
    args = parser.parse_args()

    report_dir = Path(args.dir)
    if not report_dir.is_dir():
        print(f"[error] Directory not found: {report_dir}")
        raise SystemExit(1)

    ReportHandler.report_dir = report_dir

    server = HTTPServer(("0.0.0.0", args.port), ReportHandler)
    print(f"[report-viewer] Serving reports from {report_dir}")
    print(f"[report-viewer] Open http://localhost:{args.port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[report-viewer] Stopped.")
        server.server_close()


if __name__ == "__main__":
    main()
