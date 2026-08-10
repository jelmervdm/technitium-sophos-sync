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


def test_format_disambiguated_name() -> None:
    """Test format_disambiguated_name appends last 4 chars of MAC address."""
    from technitium_sophos_sync.sync import format_disambiguated_name

    assert format_disambiguated_name("SonosZP", "00-11-22-33-44-55") == "SonosZP_4455"
    assert format_disambiguated_name("SonosZP", "001122334455") == "SonosZP_4455"
    assert format_disambiguated_name("SonosZP", "") == "SonosZP_0000"


def test_prepare_lease_names_duplicates_only() -> None:
    """Test prepare_lease_names in 'duplicates_only' mode only suffixes duplicate hostnames."""
    from technitium_sophos_sync.sync import prepare_lease_names

    leases = [
        DHCPLease(name="SonosZP", ip="10.0.0.1", mac="00-11-22-33-44-55", is_reserved=False),
        DHCPLease(name="SonosZP", ip="10.0.0.2", mac="00-11-22-33-AA-BB", is_reserved=False),
        DHCPLease(name="UniqueHost", ip="10.0.0.3", mac="00-11-22-33-CC-DD", is_reserved=False),
    ]

    named_leases = prepare_lease_names(leases, mode="duplicates_only")
    assert len(named_leases) == 3
    assert named_leases[0] == (leases[0], "SonosZP_4455")
    assert named_leases[1] == (leases[1], "SonosZP_AABB")
    assert named_leases[2] == (leases[2], "UniqueHost")


def test_prepare_lease_names_modes() -> None:
    """Test prepare_lease_names in 'always' and 'off' modes."""
    from technitium_sophos_sync.sync import prepare_lease_names

    leases = [
        DHCPLease(name="HostA", ip="10.0.0.1", mac="00-11-22-33-44-55", is_reserved=False),
        DHCPLease(name="HostB", ip="10.0.0.2", mac="00-11-22-33-AA-BB", is_reserved=False),
    ]

    always_leases = prepare_lease_names(leases, mode="always")
    assert always_leases[0][1] == "HostA_4455"
    assert always_leases[1][1] == "HostB_AABB"

    off_leases = prepare_lease_names(leases, mode="off")
    assert off_leases[0][1] == "HostA"
    assert off_leases[1][1] == "HostB"


def test_sync_engine_ip_conflict_skipping(mock_settings: Settings) -> None:
    """Test that leases targeting an IP bound to a different Sophos user are skipped."""
    from technitium_sophos_sync.sophos import SophosUsersState

    mock_tech = MagicMock()
    mock_sophos = MagicMock()

    mock_tech.get_dhcp_leases.return_value = [
        DHCPLease(
            name="NewDHCPDevice",
            ip="192.168.1.50",
            mac="00-11-22-33-44-55",
            is_reserved=False,
        ),
    ]

    # IP 192.168.1.50 is owned by manual user 'manual_admin' in Sophos
    mock_sophos.get_existing_clientless_users_state.return_value = SophosUsersState(
        by_name={"manual_admin": "192.168.1.50"},
        by_ip={"192.168.1.50": "manual_admin"},
    )

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

    # Ensure upsert_clientless_user was NOT called because IP is conflicted
    mock_sophos.upsert_clientless_user.assert_not_called()



