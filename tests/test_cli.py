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


@patch("technitium_sophos_sync.cli.SyncEngine")
def test_cli_timeouts(mock_engine_cls: MagicMock) -> None:
    """Test specifying timeout CLI options."""
    mock_engine = mock_engine_cls.return_value
    mock_engine.run_sync.return_value = SyncResult(total_leases=0, created=0, updated=0)

    runner = CliRunner()
    result = runner.invoke(
        main,
        [
            "--sophos-timeout",
            "45.0",
            "--technitium-timeout",
            "20.0",
            "--once",
        ],
    )

    assert result.exit_code == 0
    settings_passed = mock_engine_cls.call_args.kwargs["settings"]
    assert settings_passed.sophos_timeout == 45.0
    assert settings_passed.technitium_timeout == 20.0


@patch("technitium_sophos_sync.cli.time.sleep")
@patch("technitium_sophos_sync.cli.SyncEngine")
def test_cli_daemon_max_consecutive_failures(mock_engine_cls: MagicMock, mock_sleep: MagicMock) -> None:
    """Test that daemon mode exits after reaching max consecutive failures."""
    from technitium_sophos_sync.sync import SyncResult

    mock_engine = mock_engine_cls.return_value
    # Return errors > 0 for consecutive runs
    mock_engine.run_sync.return_value = SyncResult(total_leases=1, errors=1)

    runner = CliRunner()
    result = runner.invoke(
        main,
        ["-i", "10"],
        env={"MAX_CONSECUTIVE_FAILURES": "2", "TECHNITIUM_TOKEN": "tok", "SOPHOS_PASS": "pass"},
    )

    assert result.exit_code == 1
    assert mock_engine.run_sync.call_count == 2


@patch("technitium_sophos_sync.cli.SyncEngine")
def test_cli_auth_failure_exit(mock_engine_cls: MagicMock) -> None:
    """Test that SophosAuthError triggers exit in daemon mode when exit_on_auth_failure is True."""
    from technitium_sophos_sync.sophos import SophosAuthError

    mock_engine = mock_engine_cls.return_value
    mock_engine.run_sync.side_effect = SophosAuthError("Auth failed")

    runner = CliRunner()
    result = runner.invoke(
        main,
        ["-i", "10"],
        env={"EXIT_ON_AUTH_FAILURE": "true", "TECHNITIUM_TOKEN": "tok", "SOPHOS_PASS": "pass"},
    )

    assert result.exit_code == 1
    assert mock_engine.run_sync.call_count == 1
