# AgentSentry

Deterministic static capability and taint reachability analyzer for Python AI agents and MCP servers.

Traditional SAST tools scan HTTP routes or isolated lines of code. **AgentSentry** starts at AI tool entrypoints (`@tool`, `@mcp.tool`, `StructuredTool.from_function`), builds a multi-hop call graph with `NetworkX`, checks whether sink arguments are tainted or structurally guarded, and flags cross-tool **Lethal Trifecta** attack chains—100% locally with zero API keys or LLM calls.

## Installation

```bash
pip install -e .
```

## Quick Start

Scan any Python AI agent or MCP server directory:

```bash
agentsentry scan ./examples
```

Output JSON for automation or fail CI pipelines on `high` / `critical` findings:

```bash
agentsentry scan ./examples --json
agentsentry scan ./examples --fail-on critical
```

## Detection Rules

| Rule | Severity | What It Detects |
| :--- | :--- | :--- |
| `AS-001` | `CRITICAL` | **Lethal Trifecta**: Untrusted network ingress + local/DB data read + unconstrained network egress |
| `AS-002` | `CRITICAL` | **Remote Code Execution Chain**: Untrusted network ingress + unguarded shell/exec sink |
| `AS-003` | `HIGH` | **Unbounded Shell Execution**: Tainted input reaching `os.system`, `subprocess.*`, `eval`, or `exec` |
| `AS-004` | `MEDIUM` | **Unguarded Filesystem Write**: File write/delete without path-containment checks (`is_relative_to` / `commonpath`) |
| `AS-005` | `MEDIUM` | **Unconstrained Network Egress**: Network POST/PUT/SEND to an LLM-controlled destination |

## False-Positive Reduction

AgentSentry suppresses noise by checking:
- **Hardcoded literals**: e.g., `requests.post("https://hooks.slack.com/...")` is marked `HARDCODED` rather than arbitrary egress.
- **Structural guards**: Path containment (`Path.is_relative_to`, `os.path.commonpath`), URL allowlist checks (`urlparse`), and static `subprocess.run([...], shell=False)` lists are marked `GUARDED`.
- **Dead code exclusion**: Unreachable helper functions not connected to any agent tool are ignored.

## Running Tests

```bash
pytest -v
```

## Limitations

- Static Python `ast` analysis cannot resolve dynamic dispatch (`getattr`, dynamic imports, or runtime-only plugin loading).
- Cross-file call resolution matches function names statically and may over-approximate when multiple modules define identically named helpers.
- Guard detection uses structural heuristics and does not formally verify bypass resistance.
