import json
from typer.testing import CliRunner

from agentsentry.cli import app
from agentsentry.graph import scan_project
from agentsentry.models import Severity

runner = CliRunner()


def test_lethal_trifecta_detection(tmp_path):
    (tmp_path / "agent.py").write_text(
        "import requests\n\n"
        "@mcp.tool()\n"
        "def fetch_webpage(url: str):\n"
        "    return requests.get(url).text\n\n"
        "@mcp.tool()\n"
        "def read_secret(path: str):\n"
        "    return open(path).read()\n\n"
        "@mcp.tool()\n"
        "def send_webhook(url: str, body: str):\n"
        "    return requests.post(url, data=body)\n",
        encoding="utf-8",
    )

    result = scan_project(tmp_path)
    rule_ids = {f.rule_id for f in result.findings}
    assert "AS-001" in rule_ids
    assert result.blast_radius_score >= 40


def test_hardcoded_webhook_suppresses_egress_false_positive(tmp_path):
    (tmp_path / "safe_agent.py").write_text(
        "import requests\n\n"
        "@mcp.tool()\n"
        "def fetch_webpage(url: str):\n"
        "    return requests.get(url).text\n\n"
        "@mcp.tool()\n"
        "def read_secret(path: str):\n"
        "    return open(path).read()\n\n"
        "@mcp.tool()\n"
        "def notify_team(msg: str):\n"
        "    return requests.post('https://hooks.slack.com/services/T00/B00/XXX', json={'text': msg})\n",
        encoding="utf-8",
    )

    result = scan_project(tmp_path)
    rule_ids = {f.rule_id for f in result.findings}
    assert "AS-001" not in rule_ids
    assert "AS-005" not in rule_ids
    assert result.blast_radius_score == 0


def test_guarded_path_write_suppresses_false_positive(tmp_path):
    (tmp_path / "guarded.py").write_text(
        "from pathlib import Path\n"
        "BASE = Path('/tmp/safe')\n\n"
        "@tool\n"
        "def save_output(filename: str, content: str):\n"
        "    target = (BASE / filename).resolve()\n"
        "    if not target.is_relative_to(BASE):\n"
        "        raise ValueError('Blocked')\n"
        "    target.write_text(content)\n",
        encoding="utf-8",
    )

    result = scan_project(tmp_path)
    assert result.findings == []
    assert result.tools[0].hits[0].guarded is True


def test_cli_json_and_fail_on_exit_codes(tmp_path):
    (tmp_path / "vuln.py").write_text(
        "import os\n"
        "@tool\n"
        "def run_cmd(cmd: str):\n"
        "    os.system(cmd)\n",
        encoding="utf-8",
    )

    res_fail = runner.invoke(app, ["scan", str(tmp_path), "--json", "--fail-on", "high"])
    assert res_fail.exit_code == 1
    payload = json.loads(res_fail.stdout)
    assert payload["findings"][0]["rule_id"] == "AS-003"
    assert payload["findings"][0]["severity"] == Severity.HIGH.value

    res_pass = runner.invoke(app, ["scan", str(tmp_path), "--fail-on", "critical"])
    assert res_pass.exit_code == 0


def test_arbitrary_variable_names_and_constant_reassignment(tmp_path):
    (tmp_path / "custom_vars.py").write_text(
        "import requests\n\n"
        "def helper_post(dest_xyz: str, body: str):\n"
        "    return requests.post(dest_xyz, data=body)\n\n"
        "@mcp.tool()\n"
        "def arbitrary_tainted(banana_123: str, msg: str):\n"
        "    hop_a = banana_123\n"
        "    hop_b = f'https://{hop_a}/leak'\n"
        "    return helper_post(hop_b, msg)\n\n"
        "@mcp.tool()\n"
        "def local_constant_var(msg: str):\n"
        "    fixed_endpoint = 'https://hooks.internal.local/notify'\n"
        "    return helper_post(fixed_endpoint, msg)\n",
        encoding="utf-8",
    )

    result = scan_project(tmp_path)
    by_name = {t.tool.name: t for t in result.tools}

    assert by_name["arbitrary_tainted"].hits[0].tainted is True
    assert by_name["local_constant_var"].hits[0].tainted is False
    assert [f.tools for f in result.findings] == [["arbitrary_tainted"]]
