from pathlib import Path
import time

import networkx as nx

from agentsentry.analyzer import (
    analyze_findings,
    compute_tainted_vars,
    detect_guard,
    is_sink_tainted,
    propagate_call_taint,
)
from agentsentry.models import ScanResult, SinkHit, ToolInfo, ToolReport
from agentsentry.parser import ParsedFunction, ParsedProject, parse_project
from agentsentry.sinks import classify_call


def _resolve_callees(fn: ParsedFunction, project: ParsedProject) -> list[str]:
    """Resolve internal project function IDs called by `fn`."""
    callees: list[str] = []
    for call in fn.calls:
        same_file_id = f"{fn.file}:{call.raw_name}"
        if same_file_id in project.functions:
            callees.append(same_file_id)
            continue

        short_name = call.resolved_name.rsplit(".", 1)[-1]
        candidates = project.by_name.get(short_name, [])
        for cand in candidates:
            if cand != fn.id:
                callees.append(cand)
    return callees


def build_call_graph(project: ParsedProject) -> nx.DiGraph:
    graph = nx.DiGraph()
    for func_id, fn in project.functions.items():
        graph.add_node(func_id)
        for callee_id in _resolve_callees(fn, project):
            graph.add_edge(func_id, callee_id)
    return graph


def _tainted_vars_along_path(path_functions: list[ParsedFunction]) -> set[str]:
    """Propagate parameter taint from tool entrypoint through intermediate helper calls."""
    tainted = compute_tainted_vars(path_functions[0])
    for caller, callee in zip(path_functions, path_functions[1:]):
        callee_tainted: set[str] = set()
        for call in caller.calls:
            if call.raw_name == callee.name or call.resolved_name.rsplit(".", 1)[-1] == callee.name:
                callee_tainted |= propagate_call_taint(tainted, call.node, callee)
        tainted = compute_tainted_vars(callee, initial_tainted=callee_tainted)
    return tainted


def scan_project(target: Path) -> ScanResult:
    start = time.perf_counter()
    project = parse_project(target)
    graph = build_call_graph(project)

    tool_reports: list[ToolReport] = []
    for func_id, fn in project.functions.items():
        if not fn.is_tool:
            continue

        reachable_ids = [func_id] + list(nx.descendants(graph, func_id))
        hits: list[SinkHit] = []
        seen_hits: set[tuple[str, str, int]] = set()

        for node_id in reachable_ids:
            node_fn = project.functions[node_id]
            try:
                path_ids = nx.shortest_path(graph, source=func_id, target=node_id)
            except nx.NetworkXNoPath:
                path_ids = [func_id]

            path_functions = [project.functions[pid] for pid in path_ids]
            path_names = [pf.name for pf in path_functions]
            tainted_vars = _tainted_vars_along_path(path_functions)

            for call in node_fn.calls:
                cap = classify_call(call.resolved_name, call.node)
                if cap is None:
                    continue
                key = (call.resolved_name, node_fn.file, call.line)
                if key in seen_hits:
                    continue
                seen_hits.add(key)

                tainted = is_sink_tainted(call.node, tainted_vars)
                guarded, guard_reason = detect_guard(cap, call.node, path_functions)

                hits.append(
                    SinkHit(
                        sink_name=call.resolved_name,
                        capability=cap,
                        file=node_fn.file,
                        line=call.line,
                        call_path=path_names + [call.resolved_name],
                        tainted=tainted,
                        guarded=guarded,
                        guard_reason=guard_reason,
                    )
                )

        tool_reports.append(
            ToolReport(
                tool=ToolInfo(
                    id=fn.id,
                    name=fn.name,
                    file=fn.file,
                    line=fn.line,
                    params=fn.params,
                    framework=fn.framework,
                ),
                hits=hits,
            )
        )

    findings, blast_score = analyze_findings(tool_reports)
    elapsed_ms = round((time.perf_counter() - start) * 1000, 2)

    return ScanResult(
        target=str(target.resolve()),
        files_scanned=project.files_scanned,
        functions_parsed=len(project.functions),
        call_edges=graph.number_of_edges(),
        scan_ms=elapsed_ms,
        tools=tool_reports,
        findings=findings,
        blast_radius_score=blast_score,
    )
