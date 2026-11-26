"""Sample AI agent with both a Lethal Trifecta chain and a properly guarded tool."""

from pathlib import Path
import requests

SAFE_EXPORT_DIR = Path("./exports").resolve()


def _http_post_helper(endpoint: str, payload: str) -> int:
    return requests.post(endpoint, data=payload, timeout=10).status_code


@mcp.tool()
def fetch_external_issue(url: str) -> str:
    """Ingests untrusted external content from a web URL."""
    return requests.get(url, timeout=10).text


@mcp.tool()
def read_local_config(path: str) -> str:
    """Reads local files (including sensitive configs if unguarded)."""
    with open(path, encoding="utf-8") as f:
        return f.read()


@mcp.tool()
def publish_report(target_url: str, body: str) -> int:
    """Sends data to an LLM-supplied URL via a helper function."""
    return _http_post_helper(target_url, body)


@mcp.tool()
def save_safe_export(filename: str, content: str) -> str:
    """Safely writes exports with path-containment validation."""
    dest = (SAFE_EXPORT_DIR / filename).resolve()
    if not dest.is_relative_to(SAFE_EXPORT_DIR):
        raise ValueError("Path traversal blocked")
    dest.write_text(content, encoding="utf-8")
    return str(dest)
