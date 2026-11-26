import ast
from dataclasses import dataclass, field
from pathlib import Path

SKIP_DIRS = {".venv", "venv", "__pycache__", ".git", "node_modules", ".pytest_cache", "dist", "build"}
TOOL_DECORATOR_NAMES = {"tool", "call_tool", "structured_tool"}


@dataclass
class CallSite:
    raw_name: str
    resolved_name: str
    line: int
    node: ast.Call


@dataclass
class ParsedFunction:
    id: str
    name: str
    file: str
    line: int
    params: list[str]
    ast_node: ast.FunctionDef | ast.AsyncFunctionDef
    is_tool: bool = False
    framework: str = "generic"
    calls: list[CallSite] = field(default_factory=list)


@dataclass
class ParsedProject:
    files_scanned: int
    functions: dict[str, ParsedFunction] = field(default_factory=dict)
    by_name: dict[str, list[str]] = field(default_factory=dict)


def _attr_to_str(node: ast.AST) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        prefix = _attr_to_str(node.value)
        return f"{prefix}.{node.attr}" if prefix else node.attr
    return None


def _detect_tool_decorator(decorators: list[ast.expr]) -> tuple[bool, str]:
    for dec in decorators:
        target = dec.func if isinstance(dec, ast.Call) else dec
        name = _attr_to_str(target)
        if not name:
            continue
        short = name.rsplit(".", 1)[-1]
        if short in TOOL_DECORATOR_NAMES:
            if "mcp" in name.lower():
                return True, "mcp"
            return True, "langchain/decorator"
    return False, "generic"


def _extract_imports(tree: ast.Module) -> dict[str, str]:
    aliases: dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                local = alias.asname or alias.name.split(".")[0]
                aliases[local] = alias.name
        elif isinstance(node, ast.ImportFrom):
            module = node.module or ""
            for alias in node.names:
                local = alias.asname or alias.name
                aliases[local] = f"{module}.{alias.name}" if module else alias.name
    return aliases


def _resolve_call_name(raw_name: str, aliases: dict[str, str]) -> str:
    parts = raw_name.split(".")
    if parts[0] in aliases:
        parts[0] = aliases[parts[0]]
        return ".".join(parts)
    return raw_name


def _iter_python_files(target: Path) -> list[Path]:
    if target.is_file():
        return [target] if target.suffix == ".py" else []
    files: list[Path] = []
    for path in target.rglob("*.py"):
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        files.append(path)
    return sorted(files)


def _collect_tool_registrations(tree: ast.Module) -> set[str]:
    """Detect StructuredTool.from_function(func=...) or Tool(..., func=...)."""
    registered: set[str] = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        call_name = _attr_to_str(node.func) or ""
        if call_name.endswith(("StructuredTool.from_function", "Tool.from_function", "Tool")):
            for kw in node.keywords:
                if kw.arg == "func" and isinstance(kw.value, ast.Name):
                    registered.add(kw.value.id)
    return registered


def parse_project(target: Path) -> ParsedProject:
    base = target.parent if target.is_file() else target
    py_files = _iter_python_files(target)
    project = ParsedProject(files_scanned=len(py_files))

    for file_path in py_files:
        try:
            source = file_path.read_text(encoding="utf-8")
            tree = ast.parse(source, filename=str(file_path))
        except (OSError, SyntaxError):
            continue

        rel_file = str(file_path.relative_to(base)) if file_path != base else file_path.name
        aliases = _extract_imports(tree)
        explicit_tools = _collect_tool_registrations(tree)

        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue

            is_tool, framework = _detect_tool_decorator(node.decorator_list)
            if not is_tool and node.name in explicit_tools:
                is_tool = True
                framework = "langchain/structured_tool"

            params = [arg.arg for arg in node.args.args if arg.arg not in ("self", "cls")]
            func_id = f"{rel_file}:{node.name}"

            calls: list[CallSite] = []
            for inner in ast.walk(node):
                if isinstance(inner, ast.Call):
                    raw_name = _attr_to_str(inner.func)
                    if raw_name:
                        resolved = _resolve_call_name(raw_name, aliases)
                        calls.append(CallSite(raw_name=raw_name, resolved_name=resolved, line=inner.lineno, node=inner))

            parsed_fn = ParsedFunction(
                id=func_id,
                name=node.name,
                file=rel_file,
                line=node.lineno,
                params=params,
                ast_node=node,
                is_tool=is_tool,
                framework=framework,
                calls=calls,
            )
            project.functions[func_id] = parsed_fn
            project.by_name.setdefault(node.name, []).append(func_id)

    return project
