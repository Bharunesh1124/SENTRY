import ast

from agentsentry.models import Capability, Finding, Severity, SinkHit, ToolReport
from agentsentry.parser import ParsedFunction

SEVERITY_WEIGHTS: dict[Severity, int] = {
    Severity.CRITICAL: 40,
    Severity.HIGH: 25,
    Severity.MEDIUM: 15,
    Severity.LOW: 5,
}


def _expr_is_tainted(expr: ast.expr, tainted_vars: set[str]) -> bool:
    """Return True if an expression references any variable in `tainted_vars`."""
    return any(isinstance(node, ast.Name) and node.id in tainted_vars for node in ast.walk(expr))


def compute_tainted_vars(fn: ParsedFunction, initial_tainted: set[str] | None = None) -> set[str]:
    """Propagate taint from parameters through local assignments regardless of variable names."""
    tainted = set(fn.params) if initial_tainted is None else set(initial_tainted)
    for stmt in ast.walk(fn.ast_node):
        if isinstance(stmt, ast.Assign) and stmt.value is not None:
            rhs_tainted = _expr_is_tainted(stmt.value, tainted)
            for target in stmt.targets:
                if isinstance(target, ast.Name):
                    if rhs_tainted:
                        tainted.add(target.id)
                    else:
                        tainted.discard(target.id)
        elif isinstance(stmt, ast.AnnAssign) and stmt.value is not None:
            if isinstance(stmt.target, ast.Name):
                if _expr_is_tainted(stmt.value, tainted):
                    tainted.add(stmt.target.id)
                else:
                    tainted.discard(stmt.target.id)
        elif isinstance(stmt, ast.AugAssign) and isinstance(stmt.target, ast.Name):
            if _expr_is_tainted(stmt.value, tainted):
                tainted.add(stmt.target.id)
    return tainted


def propagate_call_taint(
    caller_tainted: set[str],
    call_node: ast.Call,
    callee_fn: ParsedFunction,
) -> set[str]:
    """Map tainted caller arguments into callee parameter names."""
    callee_tainted: set[str] = set()
    for idx, arg in enumerate(call_node.args):
        if idx < len(callee_fn.params) and _expr_is_tainted(arg, caller_tainted):
            callee_tainted.add(callee_fn.params[idx])
    for kw in call_node.keywords:
        if kw.arg and kw.arg in callee_fn.params and _expr_is_tainted(kw.value, caller_tainted):
            callee_tainted.add(kw.arg)
    return callee_tainted


def is_sink_tainted(call_node: ast.Call, tainted_vars: set[str] | None = None) -> bool:
    """Return True if the sink's target argument depends on tainted variables."""
    target_arg: ast.expr | None = call_node.args[0] if call_node.args else None
    if target_arg is None:
        for kw in call_node.keywords:
            if kw.arg in ("url", "cmd", "command", "file", "path", "sql"):
                target_arg = kw.value
                break
    if target_arg is None:
        return True
    if isinstance(target_arg, ast.Constant):
        return False
    if tainted_vars is not None:
        return _expr_is_tainted(target_arg, tainted_vars)
    return True


def detect_guard(
    capability: Capability,
    call_node: ast.Call,
    path_functions: list[ParsedFunction],
) -> tuple[bool, str | None]:
    """Detect structural safety guards along the call path to suppress false positives."""
    # 1. Subprocess static command list with shell=False
    if capability == Capability.SHELL_EXEC and call_node.args:
        shell_true = any(
            kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True
            for kw in call_node.keywords
        )
        if not shell_true and isinstance(call_node.args[0], ast.List):
            if all(isinstance(elt, ast.Constant) for elt in call_node.args[0].elts):
                return True, "Static command list (shell=False)"

    # 2. Inspect AST of functions in the call chain for containment / allowlist checks
    called_names: set[str] = set()
    for fn in path_functions:
        for c in fn.calls:
            called_names.add(c.resolved_name)
            called_names.add(c.raw_name.rsplit(".", 1)[-1])

    if capability in (Capability.FS_READ, Capability.FS_WRITE):
        if any(name in called_names for name in ("is_relative_to", "commonpath", "os.path.commonpath")):
            return True, "Path containment check (is_relative_to/commonpath)"

    if capability in (Capability.NET_EGRESS, Capability.NET_INGRESS):
        if any("urlparse" in name or "allowlist" in name.lower() for name in called_names):
            return True, "URL/domain validation check"

    return False, None


def _active_hits(tool_reports: list[ToolReport], cap: Capability) -> list[tuple[str, SinkHit]]:
    results: list[tuple[str, SinkHit]] = []
    for tr in tool_reports:
        for hit in tr.hits:
            if hit.capability == cap and hit.tainted and not hit.guarded:
                results.append((tr.tool.name, hit))
    return results


def _all_hits(tool_reports: list[ToolReport], cap: Capability) -> list[tuple[str, SinkHit]]:
    results: list[tuple[str, SinkHit]] = []
    for tr in tool_reports:
        for hit in tr.hits:
            if hit.capability == cap:
                results.append((tr.tool.name, hit))
    return results


def analyze_findings(tool_reports: list[ToolReport]) -> tuple[list[Finding], int]:
    """Evaluate intra-tool and cross-tool findings and compute blast radius score (0-100)."""
    findings: list[Finding] = []

    ingress_hits = _all_hits(tool_reports, Capability.NET_INGRESS)
    data_read_hits = _all_hits(tool_reports, Capability.FS_READ) + _all_hits(tool_reports, Capability.DB_EXEC)
    egress_hits = _active_hits(tool_reports, Capability.NET_EGRESS)
    shell_hits = _active_hits(tool_reports, Capability.SHELL_EXEC)
    fs_write_hits = _active_hits(tool_reports, Capability.FS_WRITE)

    # AS-001: Lethal Trifecta (Untrusted Ingress + Private Data Read + Unconstrained Egress)
    if ingress_hits and data_read_hits and egress_hits:
        involved = sorted({t for t, _ in ingress_hits + data_read_hits + egress_hits})
        witnesses = [
            f"[INGRESS] {t}: {' -> '.join(h.call_path)} ({h.file}:{h.line})" for t, h in ingress_hits[:2]
        ] + [
            f"[DATA]    {t}: {' -> '.join(h.call_path)} ({h.file}:{h.line})" for t, h in data_read_hits[:2]
        ] + [
            f"[EGRESS]  {t}: {' -> '.join(h.call_path)} ({h.file}:{h.line})" for t, h in egress_hits[:2]
        ]
        findings.append(
            Finding(
                rule_id="AS-001",
                title="Lethal Trifecta: Data Exfiltration Chain",
                severity=Severity.CRITICAL,
                tools=involved,
                description=(
                    "Agent combines untrusted external input, local/DB data access, and "
                    "unconstrained network egress. Indirect prompt injection can exfiltrate private data."
                ),
                witness_paths=witnesses,
                recommendation="Remove unbounded egress or enforce a strict domain allowlist + path sandboxing.",
            )
        )

    # AS-002: Remote Code Execution Chain (Untrusted Ingress + Unbounded Shell)
    if ingress_hits and shell_hits:
        involved = sorted({t for t, _ in ingress_hits + shell_hits})
        witnesses = [
            f"[INGRESS] {t}: {' -> '.join(h.call_path)} ({h.file}:{h.line})" for t, h in ingress_hits[:2]
        ] + [
            f"[EXEC]    {t}: {' -> '.join(h.call_path)} ({h.file}:{h.line})" for t, h in shell_hits[:2]
        ]
        findings.append(
            Finding(
                rule_id="AS-002",
                title="Remote Code Execution Chain",
                severity=Severity.CRITICAL,
                tools=involved,
                description="Agent ingests untrusted network content and exposes an unguarded shell/exec sink.",
                witness_paths=witnesses,
                recommendation="Replace shell execution with typed Python APIs or strict command allowlists (shell=False).",
            )
        )

    # AS-003: Unbounded Shell Execution
    for tool_name, hit in shell_hits:
        findings.append(
            Finding(
                rule_id="AS-003",
                title="Unbounded Shell / Code Execution",
                severity=Severity.HIGH,
                tools=[tool_name],
                description=f"Tool `{tool_name}` passes tainted input into `{hit.sink_name}` without a static allowlist.",
                witness_paths=[f"{' -> '.join(hit.call_path)} ({hit.file}:{hit.line})"],
                recommendation="Use subprocess.run([...], shell=False) with fixed commands or validate against an allowlist.",
            )
        )

    # AS-004: Unguarded Filesystem Write
    for tool_name, hit in fs_write_hits:
        findings.append(
            Finding(
                rule_id="AS-004",
                title="Unguarded Filesystem Write",
                severity=Severity.MEDIUM,
                tools=[tool_name],
                description=f"Tool `{tool_name}` writes/deletes files via `{hit.sink_name}` without path containment.",
                witness_paths=[f"{' -> '.join(hit.call_path)} ({hit.file}:{hit.line})"],
                recommendation="Validate resolved paths using `Path(p).resolve().is_relative_to(SAFE_DIR)`.",
            )
        )

    # AS-005: Unconstrained Network Egress
    for tool_name, hit in egress_hits:
        findings.append(
            Finding(
                rule_id="AS-005",
                title="Unconstrained Network Egress",
                severity=Severity.MEDIUM,
                tools=[tool_name],
                description=f"Tool `{tool_name}` sends data to an LLM-controlled destination via `{hit.sink_name}`.",
                witness_paths=[f"{' -> '.join(hit.call_path)} ({hit.file}:{hit.line})"],
                recommendation="Hardcode target endpoints or validate destination domains against an explicit allowlist.",
            )
        )

    score = min(100, sum(SEVERITY_WEIGHTS[f.severity] for f in findings))
    return findings, score
