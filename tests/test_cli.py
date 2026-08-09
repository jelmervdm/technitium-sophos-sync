"""Unit tests for CLI interface."""

from unittest.mock import MagicMock, patch

from click.testing import CliRunner

from technitium_sophos_sync.cli import main
from technitium_sophos_sync.sync import SyncResult


def test_cli_help() -> None:
    """Test CLI --help output."""
    runner = CliRunner()
    result = runner.invoke(main, ["--help"])
    assert result.exit_code == 0
    assert "Technitium DHCP to Sophos Firewall Clientless User Sync utility" in result.output
    assert "--dry-run" in result.output
    assert "--once" in result.output


def test_cli_version() -> None:
    """Test CLI --version output."""
    runner = CliRunner()
    result = runner.invoke(main, ["--version"])
    assert result.exit_code == 0
    assert "technitium-sophos-sync, version" in result.output


@patch("technitium_sophos_sync.cli.SyncEngine")
def test_cli_once_execution(mock_engine_cls: MagicMock) -> None:
    """Test running CLI with --once flag."""
    mock_engine = mock_engine_cls.return_value
    mock_engine.run_sync.return_value = SyncResult(total_leases=2, created=1, updated=1)

    runner = CliRunner()
    result = runner.invoke(
        main,
        [
            "--technitium-token",
            "token123",
            "--sophos-pass",
            "pass123",
            "--once",
            "--dry-run",
        ],
    )

    assert result.exit_code == 0
    assert mock_engine.run_sync.call_count == 1
