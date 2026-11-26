from agentsentry.graph import scan_project
from agentsentry.models import Capability


def test_multihop_reachability_and_aliases(tmp_path):
    (tmp_path / "helpers.py").write_text(
        "import subprocess as sp\n"
        "def run_hidden(cmd: str):\n"
        "    return sp.run(cmd, shell=True)\n",
        encoding="utf-8",
    )
    (tmp_path / "agent.py").write_text(
        "from helpers import run_hidden\n"
        "def mcp_tool(fn): return fn\n\n"
        "@mcp.tool()\n"
        "def execute_task(command: str):\n"
        "    return run_hidden(command)\n\n"
        "def unused_dead_code():\n"
        "    import os\n"
        "    os.system('whoami')\n",
        encoding="utf-8",
    )

    result = scan_project(tmp_path)
    assert result.files_scanned == 2
    assert len(result.tools) == 1

    tool_report = result.tools[0]
    assert tool_report.tool.name == "execute_task"
    assert tool_report.tool.framework == "mcp"
    assert Capability.SHELL_EXEC in tool_report.capabilities
    assert tool_report.hits[0].call_path == ["execute_task", "run_hidden", "subprocess.run"]


def test_open_read_vs_write_classification(tmp_path):
    (tmp_path / "tools.py").write_text(
        "@tool\n"
        "def read_notes(path: str):\n"
        "    with open(path) as f:\n"
        "        return f.read()\n\n"
        "@tool\n"
        "def write_notes(path: str, text: str):\n"
        "    with open(path, 'w') as f:\n"
        "        f.write(text)\n",
        encoding="utf-8",
    )

    result = scan_project(tmp_path)
    by_name = {t.tool.name: t for t in result.tools}

    assert by_name["read_notes"].capabilities == {Capability.FS_READ}
    assert by_name["write_notes"].capabilities == {Capability.FS_WRITE}
