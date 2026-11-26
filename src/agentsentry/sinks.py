import ast

from agentsentry.models import Capability

EXACT_SINKS: dict[str, Capability] = {
    # Shell / Code Execution
    "os.system": Capability.SHELL_EXEC,
    "os.popen": Capability.SHELL_EXEC,
    "subprocess.run": Capability.SHELL_EXEC,
    "subprocess.Popen": Capability.SHELL_EXEC,
    "subprocess.call": Capability.SHELL_EXEC,
    "subprocess.check_output": Capability.SHELL_EXEC,
    "subprocess.check_call": Capability.SHELL_EXEC,
    "eval": Capability.SHELL_EXEC,
    "exec": Capability.SHELL_EXEC,
    # Filesystem Read
    "os.listdir": Capability.FS_READ,
    "os.walk": Capability.FS_READ,
    "glob.glob": Capability.FS_READ,
    # Filesystem Write / Delete
    "os.remove": Capability.FS_WRITE,
    "os.unlink": Capability.FS_WRITE,
    "os.rmdir": Capability.FS_WRITE,
    "shutil.rmtree": Capability.FS_WRITE,
    "shutil.copy": Capability.FS_WRITE,
    "shutil.move": Capability.FS_WRITE,
    # Network Ingress
    "requests.get": Capability.NET_INGRESS,
    "httpx.get": Capability.NET_INGRESS,
    "urllib.request.urlopen": Capability.NET_INGRESS,
    "urllib.request.urlretrieve": Capability.NET_INGRESS,
    # Network Egress
    "requests.post": Capability.NET_EGRESS,
    "requests.put": Capability.NET_EGRESS,
    "requests.patch": Capability.NET_EGRESS,
    "requests.delete": Capability.NET_EGRESS,
    "requests.request": Capability.NET_EGRESS,
    "httpx.post": Capability.NET_EGRESS,
    "httpx.put": Capability.NET_EGRESS,
    "httpx.patch": Capability.NET_EGRESS,
    "httpx.delete": Capability.NET_EGRESS,
    "httpx.request": Capability.NET_EGRESS,
}

# Method names on arbitrary objects (e.g. Path(...).read_text(), cursor.execute())
METHOD_SINKS: dict[str, Capability] = {
    "read_text": Capability.FS_READ,
    "read_bytes": Capability.FS_READ,
    "write_text": Capability.FS_WRITE,
    "write_bytes": Capability.FS_WRITE,
    "unlink": Capability.FS_WRITE,
    "sendmail": Capability.NET_EGRESS,
    "send_message": Capability.NET_EGRESS,
    "execute": Capability.DB_EXEC,
    "executemany": Capability.DB_EXEC,
    "executescript": Capability.DB_EXEC,
}


def _open_capability(call_node: ast.Call) -> Capability:
    """Differentiate open() read vs write modes."""
    mode = "r"
    if len(call_node.args) >= 2 and isinstance(call_node.args[1], ast.Constant):
        if isinstance(call_node.args[1].value, str):
            mode = call_node.args[1].value
    for kw in call_node.keywords:
        if kw.arg == "mode" and isinstance(kw.value, ast.Constant) and isinstance(kw.value.value, str):
            mode = kw.value.value
    if any(flag in mode for flag in ("w", "a", "x", "+")):
        return Capability.FS_WRITE
    return Capability.FS_READ


def classify_call(resolved_name: str, call_node: ast.Call) -> Capability | None:
    """Return Capability if a resolved call expression matches a known sink."""
    if resolved_name == "open":
        return _open_capability(call_node)
    if resolved_name in EXACT_SINKS:
        return EXACT_SINKS[resolved_name]
    method = resolved_name.rsplit(".", 1)[-1]
    if method in METHOD_SINKS:
        return METHOD_SINKS[method]
    return None
