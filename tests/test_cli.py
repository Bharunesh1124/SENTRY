from typer.testing import CliRunner

from agentsentry.cli import app

runner = CliRunner()


def test_scan_smoke(tmp_path):
    result = runner.invoke(app, ["scan", str(tmp_path)])
    assert result.exit_code == 0
    assert "AgentSentry" in result.stdout
