"""Unit tests for SyncEngine."""

from unittest.mock import MagicMock

from technitium_sophos_sync.config import Settings
from technitium_sophos_sync.sync import SyncEngine
from technitium_sophos_sync.technitium import DHCPLease


def test_sync_engine_creates_and_updates(mock_settings: Settings) -> None:
    """Test SyncEngine creation, update, and unchanged branches."""
    mock_tech = MagicMock()
    mock_sophos = MagicMock()

    # Technitium returns 3 leases: 1 new, 1 changed IP, 1 unchanged IP
    mock_tech.get_dhcp_leases.return_value = [
        DHCPLease(name="new_device", ip="192.168.1.10", mac="00-11-22", is_reserved=False),
        DHCPLease(name="updated_device", ip="192.168.1.20", mac="33-44-55", is_reserved=True),
        DHCPLease(name="same_device", ip="192.168.1.30", mac="66-77-88", is_reserved=True),
    ]

    # Sophos has updated_device with old IP and same_device with current IP
    mock_sophos.get_existing_clientless_users.return_value = {
        "updated_device": "192.168.1.19",
        "same_device": "192.168.1.30",
    }
    mock_sophos.upsert_clientless_user.return_value = True

    engine = SyncEngine(
        settings=mock_settings,
        technitium_client=mock_tech,
        sophos_client=mock_sophos,
    )

    result = engine.run_sync()

    assert result.total_leases == 3
    assert result.created == 1
    assert result.updated == 1
    assert result.unchanged == 1
    assert result.errors == 0

    # Ensure upsert_clientless_user was called for new_device and updated_device
    assert mock_sophos.upsert_clientless_user.call_count == 2
    mock_sophos.upsert_clientless_user.assert_any_call(
        "new_device", "192.168.1.10", operation="add"
    )
    mock_sophos.upsert_clientless_user.assert_any_call(
        "updated_device", "192.168.1.20", operation="update"
    )


def test_sync_engine_dry_run(mock_settings: Settings) -> None:
    """Test dry-run mode skips Sophos API modifications."""
    mock_settings.dry_run = True

    mock_tech = MagicMock()
    mock_sophos = MagicMock()

    mock_tech.get_dhcp_leases.return_value = [
        DHCPLease(name="new_device", ip="192.168.1.10", mac="00-11-22", is_reserved=False),
    ]
    mock_sophos.get_existing_clientless_users.return_value = {}

    engine = SyncEngine(
        settings=mock_settings,
        technitium_client=mock_tech,
        sophos_client=mock_sophos,
    )

    result = engine.run_sync()

    assert result.total_leases == 1
    assert result.created == 1
    assert result.errors == 0

    # Upsert MUST NOT be called in dry-run mode
    mock_sophos.upsert_clientless_user.assert_not_called()


def test_sync_engine_case_insensitive_matching(mock_settings: Settings) -> None:
    """Test SyncEngine handles case differences between Technitium and Sophos."""
    mock_tech = MagicMock()
    mock_sophos = MagicMock()

    # Technitium returns mixed case lease name
    mock_tech.get_dhcp_leases.return_value = [
        DHCPLease(
            name="Mac_main_heberhouses_com",
            ip="10.20.1.13",
            mac="00-11-22",
            is_reserved=True,
        ),
    ]

    # Sophos has lowercased and mixed-cased keys from get_existing_clientless_users
    mock_sophos.get_existing_clientless_users.return_value = {
        "mac_main_heberhouses_com": "10.20.1.13",
        "Mac_main_heberhouses_com": "10.20.1.13",
    }
    mock_sophos.upsert_clientless_user.return_value = True

    engine = SyncEngine(
        settings=mock_settings,
        technitium_client=mock_tech,
        sophos_client=mock_sophos,
    )

    result = engine.run_sync()

    assert result.total_leases == 1
    assert result.created == 0
    assert result.updated == 0
    assert result.unchanged == 1
    assert result.errors == 0

    mock_sophos.upsert_clientless_user.assert_not_called()

