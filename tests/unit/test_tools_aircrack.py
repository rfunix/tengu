"""Unit tests for aircrack_scan: interface sanitization, scan time clamping, CSV parsing."""
from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

# ---------------------------------------------------------------------------
# Helpers / fixtures
# ---------------------------------------------------------------------------

_MOD = "tengu.tools.wireless.aircrack"


def _make_ctx() -> MagicMock:
    ctx = MagicMock()
    ctx.report_progress = AsyncMock()
    return ctx


def _make_rate_limited_mock() -> MagicMock:
    mock = MagicMock()
    mock.return_value.__aenter__ = AsyncMock(return_value=None)
    mock.return_value.__aexit__ = AsyncMock(return_value=False)
    return mock


def _make_audit_mock() -> MagicMock:
    audit = MagicMock()
    audit.log_tool_call = AsyncMock()
    return audit


def _make_proc_mock() -> MagicMock:
    proc = MagicMock()
    proc.terminate = MagicMock()
    proc.communicate = AsyncMock(return_value=(b"", b""))
    return proc


@pytest.fixture
def ctx():
    return _make_ctx()


def _make_csv_content(num_aps: int = 2, include_station_line: bool = False) -> str:
    """Generate fake airodump-ng CSV content."""
    header = "BSSID, First time seen, Last time seen, channel, Speed, Privacy, Cipher, Authentication, Power, # beacons, # IV, LAN IP, ID-length, ESSID, Key"
    rows = []
    for i in range(num_aps):
        row = (
            f"AA:BB:CC:DD:EE:0{i}, "  # BSSID (parts[0])
            f"2024-01-01 00:00:00, "   # first_seen (parts[1])
            f"2024-01-01 00:01:00, "   # last_seen (parts[2])
            f"{i + 1}, "              # channel (parts[3])
            f"54, "                   # speed (parts[4])
            f"WPA2, "                 # privacy (parts[5])
            f"CCMP, "                 # cipher (parts[6])
            f"PSK, "                  # auth (parts[7])
            f"-50, "                  # power (parts[8])
            f"100, "                  # beacons (parts[9])
            f"0, "                    # IV (parts[10])
            f"0.0.0.0, "             # LAN IP (parts[11])
            f"8, "                    # ID-length (parts[12])
            f"TestNet{i}"             # SSID (parts[13])
        )
        rows.append(row)

    lines = [header] + rows
    if include_station_line:
        lines.append("")
        lines.append("Station MAC, First time seen, Last time seen, Power, # packets, BSSID, Probed ESSIDs")
        lines.append("FF:FF:FF:FF:FF:FF, 2024-01-01 00:00:00, 2024-01-01 00:01:00, -60, 10, AA:BB:CC:DD:EE:00, TestNet0")
    return "\n".join(lines)


async def _run_aircrack(ctx, interface="wlan0mon", scan_time=30,
                        csv_content=None, csv_exists=True):
    """Run aircrack_scan under full mock."""
    from tengu.tools.wireless.aircrack import aircrack_scan

    rate_limited_mock = _make_rate_limited_mock()
    audit_mock = _make_audit_mock()
    proc_mock = _make_proc_mock()

    with (
        patch(f"{_MOD}.get_audit_logger", return_value=audit_mock),
        patch(f"{_MOD}.rate_limited", rate_limited_mock),
        patch(f"{_MOD}.resolve_tool_path", return_value="/usr/sbin/airodump-ng"),
        patch("asyncio.create_subprocess_exec", return_value=proc_mock) as mock_exec,
        patch("asyncio.sleep", new=AsyncMock(return_value=None)),
        patch(f"{_MOD}.Path") as mock_path_cls,
    ):
        # Configure Path mock for the CSV file
        mock_csv = MagicMock()
        mock_csv.exists.return_value = csv_exists
        if csv_content is not None:
            mock_csv.read_text.return_value = csv_content
        else:
            mock_csv.read_text.return_value = ""
        mock_csv.unlink = MagicMock()
        mock_path_cls.return_value = mock_csv

        result = await aircrack_scan(ctx, interface=interface, scan_time=scan_time)
        return result, mock_exec, proc_mock, mock_csv


# ---------------------------------------------------------------------------
# TestAircrackInterfaceSanitization
# ---------------------------------------------------------------------------


class TestAircrackInterfaceSanitization:
    async def test_interface_bad_chars_stripped(self, ctx):
        result, _, _, _ = await _run_aircrack(ctx, interface="wlan0;evil")
        # The sanitized interface should be used — semicolon stripped
        assert result["interface"] == "wlan0evil"

    async def test_empty_interface_defaults_to_wlan0(self, ctx):
        result, _, _, _ = await _run_aircrack(ctx, interface="")
        assert result["interface"] == "wlan0"

    async def test_valid_interface_preserved(self, ctx):
        result, _, _, _ = await _run_aircrack(ctx, interface="wlan0mon")
        assert result["interface"] == "wlan0mon"

    async def test_interface_with_hyphen_preserved(self, ctx):
        result, _, _, _ = await _run_aircrack(ctx, interface="wlan-0")
        assert result["interface"] == "wlan-0"

    async def test_interface_special_chars_stripped(self, ctx):
        result, _, _, _ = await _run_aircrack(ctx, interface="wlan0$@!")
        assert "$" not in result["interface"]
        assert "@" not in result["interface"]
        assert "!" not in result["interface"]


# ---------------------------------------------------------------------------
# TestAircrackScanTimeClamping
# ---------------------------------------------------------------------------


class TestAircrackScanTimeClamping:
    async def test_scan_time_clamped_min(self, ctx):
        # scan_time=1 is below minimum 5; asyncio.sleep should be called with 5
        from tengu.tools.wireless.aircrack import aircrack_scan

        rate_limited_mock = _make_rate_limited_mock()
        audit_mock = _make_audit_mock()
        proc_mock = _make_proc_mock()

        with (
            patch(f"{_MOD}.get_audit_logger", return_value=audit_mock),
            patch(f"{_MOD}.rate_limited", rate_limited_mock),
            patch(f"{_MOD}.resolve_tool_path", return_value="/usr/sbin/airodump-ng"),
            patch("asyncio.create_subprocess_exec", return_value=proc_mock),
            patch("asyncio.sleep", new=AsyncMock(return_value=None)) as mock_sleep,
            patch(f"{_MOD}.Path") as mock_path_cls,
        ):
            mock_csv = MagicMock()
            mock_csv.exists.return_value = False
            mock_path_cls.return_value = mock_csv
            ctx2 = _make_ctx()
            await aircrack_scan(ctx2, interface="wlan0", scan_time=1)
            # Sleep should be called with the clamped value (5)
            mock_sleep.assert_called_once_with(5)

    async def test_scan_time_clamped_max(self, ctx):
        # scan_time=600 is above maximum 300; asyncio.sleep should be called with 300
        from tengu.tools.wireless.aircrack import aircrack_scan

        rate_limited_mock = _make_rate_limited_mock()
        audit_mock = _make_audit_mock()
        proc_mock = _make_proc_mock()

        with (
            patch(f"{_MOD}.get_audit_logger", return_value=audit_mock),
            patch(f"{_MOD}.rate_limited", rate_limited_mock),
            patch(f"{_MOD}.resolve_tool_path", return_value="/usr/sbin/airodump-ng"),
            patch("asyncio.create_subprocess_exec", return_value=proc_mock),
            patch("asyncio.sleep", new=AsyncMock(return_value=None)) as mock_sleep,
            patch(f"{_MOD}.Path") as mock_path_cls,
        ):
            mock_csv = MagicMock()
            mock_csv.exists.return_value = False
            mock_path_cls.return_value = mock_csv
            ctx2 = _make_ctx()
            await aircrack_scan(ctx2, interface="wlan0", scan_time=600)
            mock_sleep.assert_called_once_with(300)

    async def test_scan_time_within_range_used(self, ctx):
        # scan_time=30 is within [5, 300]; asyncio.sleep should be called with 30
        from tengu.tools.wireless.aircrack import aircrack_scan

        rate_limited_mock = _make_rate_limited_mock()
        audit_mock = _make_audit_mock()
        proc_mock = _make_proc_mock()

        with (
            patch(f"{_MOD}.get_audit_logger", return_value=audit_mock),
            patch(f"{_MOD}.rate_limited", rate_limited_mock),
            patch(f"{_MOD}.resolve_tool_path", return_value="/usr/sbin/airodump-ng"),
            patch("asyncio.create_subprocess_exec", return_value=proc_mock),
            patch("asyncio.sleep", new=AsyncMock(return_value=None)) as mock_sleep,
            patch(f"{_MOD}.Path") as mock_path_cls,
        ):
            mock_csv = MagicMock()
            mock_csv.exists.return_value = False
            mock_path_cls.return_value = mock_csv
            ctx2 = _make_ctx()
            await aircrack_scan(ctx2, interface="wlan0", scan_time=30)
            mock_sleep.assert_called_once_with(30)


# ---------------------------------------------------------------------------
# TestAircrackSubprocess
# ---------------------------------------------------------------------------


class TestAircrackSubprocess:
    async def test_subprocess_called_with_airodump(self, ctx):
        _, mock_exec, _, _ = await _run_aircrack(ctx, interface="wlan0mon")
        mock_exec.assert_called_once()
        call_args = mock_exec.call_args[0]
        assert "/usr/sbin/airodump-ng" in call_args

    async def test_proc_terminate_called_after_scan_time(self, ctx):
        _, _, proc_mock, _ = await _run_aircrack(ctx, interface="wlan0mon")
        proc_mock.terminate.assert_called_once()

    async def test_proc_communicate_called(self, ctx):
        _, _, proc_mock, _ = await _run_aircrack(ctx)
        proc_mock.communicate.assert_called_once()


# ---------------------------------------------------------------------------
# TestAircrackCsvParsing
# ---------------------------------------------------------------------------


class TestAircrackCsvParsing:
    async def test_csv_parsed_access_points(self, ctx):
        csv = _make_csv_content(num_aps=2)
        result, _, _, _ = await _run_aircrack(ctx, csv_content=csv)
        assert result["networks_found"] == 2

    async def test_access_point_fields_populated(self, ctx):
        csv = _make_csv_content(num_aps=1)
        result, _, _, _ = await _run_aircrack(ctx, csv_content=csv)
        ap = result["access_points"][0]
        assert "bssid" in ap
        assert "ssid" in ap
        assert "channel" in ap
        assert "privacy" in ap

    async def test_station_mac_line_stops_parsing(self, ctx):
        csv = _make_csv_content(num_aps=2, include_station_line=True)
        result, _, _, _ = await _run_aircrack(ctx, csv_content=csv)
        # Station MAC line stops the AP parsing — only 2 APs before that line
        assert result["networks_found"] == 2

    async def test_csv_lines_with_fewer_than_14_parts_skipped(self, ctx):
        # A line with only 5 parts should be skipped
        csv = "AA:BB:CC:DD:EE:FF, col1, col2, col3, col4\n"
        result, _, _, _ = await _run_aircrack(ctx, csv_content=csv)
        # The header line "BSSID" is filtered but this line has fewer than 14 parts
        # and doesn't contain "BSSID" — so it's attempted but skipped due to len check
        assert result["networks_found"] == 0

    async def test_no_csv_file_gives_empty_list(self, ctx):
        result, _, _, _ = await _run_aircrack(ctx, csv_exists=False)
        assert result["networks_found"] == 0
        assert result["access_points"] == []

    async def test_csv_file_unlink_called_after_parsing(self, ctx):
        csv = _make_csv_content(num_aps=1)
        _, _, _, mock_csv = await _run_aircrack(ctx, csv_content=csv)
        mock_csv.unlink.assert_called_once()

    async def test_ssid_extracted_from_part_13(self, ctx):
        csv = _make_csv_content(num_aps=1)
        result, _, _, _ = await _run_aircrack(ctx, csv_content=csv)
        assert result["access_points"][0]["ssid"] == "TestNet0"

    async def test_bssid_header_line_skipped(self, ctx):
        csv = "BSSID, First time seen, channel, Speed, Privacy, Cipher, Auth, Power, beacons, IV, LAN IP, len, ESSID, Key\n"
        result, _, _, _ = await _run_aircrack(ctx, csv_content=csv)
        assert result["networks_found"] == 0


# ---------------------------------------------------------------------------
# TestAircrackReturnStructure
# ---------------------------------------------------------------------------


class TestAircrackReturnStructure:
    async def test_return_keys_present(self, ctx):
        result, _, _, _ = await _run_aircrack(ctx)
        expected_keys = {
            "tool", "interface", "scan_duration_seconds",
            "networks_found", "access_points", "warning",
        }
        assert expected_keys.issubset(result.keys())

    async def test_tool_name_is_airodump_ng(self, ctx):
        result, _, _, _ = await _run_aircrack(ctx)
        assert result["tool"] == "airodump-ng"

    async def test_warning_field_present(self, ctx):
        result, _, _, _ = await _run_aircrack(ctx)
        assert "warning" in result
        assert len(result["warning"]) > 0

    async def test_no_allowlist_check_and_no_get_config(self, ctx):
        """checkov/aircrack don't call get_config or allowlist — verify module imports."""
        import tengu.tools.wireless.aircrack as mod
        # Confirm make_allowlist_from_config is not imported in aircrack module
        assert not hasattr(mod, "make_allowlist_from_config")
        assert not hasattr(mod, "get_config")
