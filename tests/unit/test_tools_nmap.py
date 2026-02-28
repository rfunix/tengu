"""Unit tests for nmap parsing helpers and configuration constants."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from tengu.tools.recon.nmap import (
    _SCAN_TYPE_FLAGS,
    _parse_nmap_xml,
    _summarize_ports,
)
from tengu.types import Host, Port

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _minimal_xml(hosts_xml: str = "") -> str:
    return f'<?xml version="1.0"?><nmaprun>{hosts_xml}</nmaprun>'


def _host_xml(
    addr: str = "192.168.1.1",
    status: str = "up",
    hostname: str = "",
    ports_xml: str = "",
    os_xml: str = "",
) -> str:
    hn = f'<hostnames><hostname name="{hostname}"/></hostnames>' if hostname else "<hostnames/>"
    os_block = f"<os>{os_xml}</os>" if os_xml else ""
    return (
        f'<host>'
        f'<status state="{status}"/>'
        f'<address addr="{addr}" addrtype="ipv4"/>'
        f"{hn}"
        f"<ports>{ports_xml}</ports>"
        f"{os_block}"
        f"</host>"
    )


def _port_xml(
    portid: int = 80,
    protocol: str = "tcp",
    state: str = "open",
    service: str = "http",
    product: str = "",
    version: str = "",
) -> str:
    svc = f'<service name="{service}" product="{product}" version="{version}"/>'
    return (
        f'<port protocol="{protocol}" portid="{portid}">'
        f'<state state="{state}"/>'
        f"{svc}"
        f"</port>"
    )


# ---------------------------------------------------------------------------
# TestParseNmapXml
# ---------------------------------------------------------------------------


class TestParseNmapXml:
    def test_empty_string_returns_empty_list(self):
        assert _parse_nmap_xml("") == []

    def test_whitespace_returns_empty_list(self):
        assert _parse_nmap_xml("   ") == []

    def test_invalid_xml_returns_empty_list(self):
        assert _parse_nmap_xml("not valid xml <<<<") == []

    def test_no_hosts_returns_empty_list(self):
        xml = _minimal_xml()
        assert _parse_nmap_xml(xml) == []

    def test_single_host_with_open_port(self):
        port_xml = _port_xml(portid=80, state="open", service="http")
        xml = _minimal_xml(_host_xml(addr="10.0.0.1", ports_xml=port_xml))
        hosts = _parse_nmap_xml(xml)
        assert len(hosts) == 1
        assert hosts[0].address == "10.0.0.1"
        assert len(hosts[0].ports) == 1
        assert hosts[0].ports[0].number == 80

    def test_closed_ports_not_included(self):
        open_port = _port_xml(portid=80, state="open")
        closed_port = _port_xml(portid=443, state="closed")
        xml = _minimal_xml(_host_xml(ports_xml=open_port + closed_port))
        hosts = _parse_nmap_xml(xml)
        assert len(hosts[0].ports) == 1
        assert hosts[0].ports[0].number == 80

    def test_hostname_parsed(self):
        xml = _minimal_xml(_host_xml(hostname="example.com"))
        hosts = _parse_nmap_xml(xml)
        assert hosts[0].hostname == "example.com"

    def test_service_version_combined(self):
        port_xml = _port_xml(portid=22, state="open", service="ssh", product="OpenSSH", version="8.9")
        xml = _minimal_xml(_host_xml(ports_xml=port_xml))
        hosts = _parse_nmap_xml(xml)
        assert "OpenSSH" in hosts[0].ports[0].version
        assert "8.9" in hosts[0].ports[0].version

    def test_os_detection_parsed(self):
        os_xml = '<osmatch name="Linux 4.15"/>'
        xml = _minimal_xml(_host_xml(os_xml=os_xml))
        hosts = _parse_nmap_xml(xml)
        assert hosts[0].os == "Linux 4.15"

    def test_multiple_hosts(self):
        h1 = _host_xml(addr="192.168.1.1")
        h2 = _host_xml(addr="192.168.1.2")
        xml = _minimal_xml(h1 + h2)
        hosts = _parse_nmap_xml(xml)
        assert len(hosts) == 2
        addrs = {h.address for h in hosts}
        assert "192.168.1.1" in addrs
        assert "192.168.1.2" in addrs

    def test_host_without_address_skipped(self):
        # ipv6 address type — the parser only accepts ipv4/ipv6
        # Use a host with only MAC address → skipped
        xml = _minimal_xml(
            '<host><address addr="00:11:22:33:44:55" addrtype="mac"/></host>'
        )
        hosts = _parse_nmap_xml(xml)
        assert hosts == []

    def test_host_status_is_up(self):
        xml = _minimal_xml(_host_xml(addr="1.2.3.4", status="up"))
        hosts = _parse_nmap_xml(xml)
        assert hosts[0].status == "up"


# ---------------------------------------------------------------------------
# TestSummarizePorts
# ---------------------------------------------------------------------------


class TestSummarizePorts:
    def test_empty_hosts_returns_empty(self):
        assert _summarize_ports([]) == []

    def test_host_with_no_ports(self):
        host = Host(address="10.0.0.1", ports=[], status="up")
        assert _summarize_ports([host]) == []

    def test_open_port_appears_in_summary(self):
        port = Port(number=80, protocol="tcp", state="open", service="http")
        host = Host(address="10.0.0.1", ports=[port], status="up")
        summary = _summarize_ports([host])
        assert len(summary) == 1
        assert summary[0]["port"] == 80
        assert summary[0]["host"] == "10.0.0.1"

    def test_multiple_ports_from_multiple_hosts(self):
        p1 = Port(number=80, protocol="tcp", state="open", service="http")
        p2 = Port(number=443, protocol="tcp", state="open", service="https")
        h1 = Host(address="10.0.0.1", ports=[p1], status="up")
        h2 = Host(address="10.0.0.2", ports=[p2], status="up")
        summary = _summarize_ports([h1, h2])
        assert len(summary) == 2


# ---------------------------------------------------------------------------
# TestScanTypeFlags
# ---------------------------------------------------------------------------


class TestScanTypeFlags:
    def test_connect_scan_uses_st_flag(self):
        assert "-sT" in _SCAN_TYPE_FLAGS["connect"]

    def test_syn_scan_uses_ss_flag(self):
        assert "-sS" in _SCAN_TYPE_FLAGS["syn"]

    def test_all_scan_types_present(self):
        for scan_type in ("syn", "connect", "udp", "version", "ping", "fast"):
            assert scan_type in _SCAN_TYPE_FLAGS


# ---------------------------------------------------------------------------
# TestNmapScan — async integration tests
# ---------------------------------------------------------------------------


_MINIMAL_NMAP_XML = '<?xml version="1.0"?><nmaprun></nmaprun>'
_NMAP_XML_WITH_HOST = (
    '<?xml version="1.0"?><nmaprun>'
    '<host><status state="up"/>'
    '<address addr="192.168.1.1" addrtype="ipv4"/>'
    '<hostnames/>'
    '<ports>'
    '<port protocol="tcp" portid="80"><state state="open"/><service name="http"/></port>'
    '</ports>'
    '</host>'
    '</nmaprun>'
)


def _make_nmap_ctx():
    ctx = AsyncMock()
    ctx.report_progress = AsyncMock()
    return ctx


def _setup_nmap_mocks(mock_run, mock_config, mock_allowlist, mock_audit, mock_rl, mock_stealth):
    cfg = MagicMock()
    cfg.tools.paths.nmap = "/usr/bin/nmap"
    cfg.tools.defaults.scan_timeout = 60
    mock_config.return_value = cfg

    al = MagicMock()
    al.check = MagicMock()
    mock_allowlist.return_value = al

    audit = MagicMock()
    audit.log_tool_call = AsyncMock()
    audit.log_target_blocked = AsyncMock()
    mock_audit.return_value = audit

    rl_ctx = MagicMock()
    rl_ctx.__aenter__ = AsyncMock(return_value=MagicMock())
    rl_ctx.__aexit__ = AsyncMock(return_value=False)
    mock_rl.return_value = rl_ctx

    stealth = MagicMock()
    stealth.enabled = False
    stealth.proxy_url = None
    mock_stealth.return_value = stealth

    mock_run.return_value = (_MINIMAL_NMAP_XML, "", 0)

    return al, audit


@patch("tengu.stealth.get_stealth_layer")
@patch("tengu.tools.recon.nmap.rate_limited")
@patch("tengu.tools.recon.nmap.resolve_tool_path", return_value="/usr/bin/nmap")
@patch("tengu.tools.recon.nmap.get_audit_logger")
@patch("tengu.tools.recon.nmap.make_allowlist_from_config")
@patch("tengu.tools.recon.nmap.get_config")
@patch("tengu.tools.recon.nmap.run_command", new_callable=AsyncMock)
class TestNmapScan:
    """Async tests for nmap_scan()."""

    async def test_nmap_blocked_target(
        self, mock_run, mock_config, mock_allowlist, mock_audit, mock_resolve, mock_rl, mock_stealth
    ):
        """Allowlist rejection propagates as an exception."""
        al, _ = _setup_nmap_mocks(mock_run, mock_config, mock_allowlist, mock_audit, mock_rl, mock_stealth)
        al.check.side_effect = ValueError("not allowed")
        ctx = _make_nmap_ctx()

        from tengu.tools.recon.nmap import nmap_scan

        with pytest.raises(ValueError, match="not allowed"):
            await nmap_scan(ctx, "192.168.1.1")

    async def test_nmap_timing_flag(
        self, mock_run, mock_config, mock_allowlist, mock_audit, mock_resolve, mock_rl, mock_stealth
    ):
        """timing='T4' results in -T4 flag in args."""
        _setup_nmap_mocks(mock_run, mock_config, mock_allowlist, mock_audit, mock_rl, mock_stealth)
        ctx = _make_nmap_ctx()

        from tengu.tools.recon.nmap import nmap_scan

        await nmap_scan(ctx, "192.168.1.1", timing="T4")

        call_args = mock_run.call_args[0][0]
        assert "-T4" in call_args

    async def test_nmap_os_detection(
        self, mock_run, mock_config, mock_allowlist, mock_audit, mock_resolve, mock_rl, mock_stealth
    ):
        """os_detection=True adds -O flag."""
        _setup_nmap_mocks(mock_run, mock_config, mock_allowlist, mock_audit, mock_rl, mock_stealth)
        ctx = _make_nmap_ctx()

        from tengu.tools.recon.nmap import nmap_scan

        await nmap_scan(ctx, "192.168.1.1", os_detection=True)

        call_args = mock_run.call_args[0][0]
        assert "-O" in call_args

    async def test_nmap_scripts(
        self, mock_run, mock_config, mock_allowlist, mock_audit, mock_resolve, mock_rl, mock_stealth
    ):
        """scripts='vuln,http-title' results in --script flag in args."""
        _setup_nmap_mocks(mock_run, mock_config, mock_allowlist, mock_audit, mock_rl, mock_stealth)
        ctx = _make_nmap_ctx()

        from tengu.tools.recon.nmap import nmap_scan

        await nmap_scan(ctx, "192.168.1.1", scripts="vuln,http-title")

        call_args = mock_run.call_args[0][0]
        assert "--script" in call_args

    async def test_nmap_stealth_proxy(
        self, mock_run, mock_config, mock_allowlist, mock_audit, mock_resolve, mock_rl, mock_stealth
    ):
        """When stealth enabled, inject_proxy_flags is called."""
        _setup_nmap_mocks(mock_run, mock_config, mock_allowlist, mock_audit, mock_rl, mock_stealth)
        stealth = MagicMock()
        stealth.enabled = True
        stealth.proxy_url = "socks5://127.0.0.1:9050"
        stealth.inject_proxy_flags = MagicMock(side_effect=lambda tool, args: args + ["--proxies", "socks5://127.0.0.1:9050"])
        mock_stealth.return_value = stealth
        ctx = _make_nmap_ctx()

        from tengu.tools.recon.nmap import nmap_scan

        await nmap_scan(ctx, "192.168.1.1")

        stealth.inject_proxy_flags.assert_called_once()

    async def test_nmap_custom_ports(
        self, mock_run, mock_config, mock_allowlist, mock_audit, mock_resolve, mock_rl, mock_stealth
    ):
        """Custom ports appear in -p flag."""
        _setup_nmap_mocks(mock_run, mock_config, mock_allowlist, mock_audit, mock_rl, mock_stealth)
        ctx = _make_nmap_ctx()

        from tengu.tools.recon.nmap import nmap_scan

        await nmap_scan(ctx, "192.168.1.1", ports="80,443")

        call_args = mock_run.call_args[0][0]
        assert "-p" in call_args
        idx = call_args.index("-p")
        assert "80" in call_args[idx + 1]

    async def test_nmap_scan_type_flags(
        self, mock_run, mock_config, mock_allowlist, mock_audit, mock_resolve, mock_rl, mock_stealth
    ):
        """scan_type='syn' results in -sS flag in args."""
        _setup_nmap_mocks(mock_run, mock_config, mock_allowlist, mock_audit, mock_rl, mock_stealth)
        ctx = _make_nmap_ctx()

        from tengu.tools.recon.nmap import nmap_scan

        await nmap_scan(ctx, "192.168.1.1", scan_type="syn")

        call_args = mock_run.call_args[0][0]
        assert "-sS" in call_args

    async def test_nmap_output_has_hosts(
        self, mock_run, mock_config, mock_allowlist, mock_audit, mock_resolve, mock_rl, mock_stealth
    ):
        """Valid XML output with host results in hosts_found > 0."""
        _setup_nmap_mocks(mock_run, mock_config, mock_allowlist, mock_audit, mock_rl, mock_stealth)
        mock_run.return_value = (_NMAP_XML_WITH_HOST, "", 0)
        ctx = _make_nmap_ctx()

        from tengu.tools.recon.nmap import nmap_scan

        result = await nmap_scan(ctx, "192.168.1.1")

        assert result["hosts_found"] == 1
        assert result["hosts"][0]["address"] == "192.168.1.1"

    async def test_nmap_tool_key(
        self, mock_run, mock_config, mock_allowlist, mock_audit, mock_resolve, mock_rl, mock_stealth
    ):
        """Result 'tool' key equals 'nmap'."""
        _setup_nmap_mocks(mock_run, mock_config, mock_allowlist, mock_audit, mock_rl, mock_stealth)
        ctx = _make_nmap_ctx()

        from tengu.tools.recon.nmap import nmap_scan

        result = await nmap_scan(ctx, "192.168.1.1")

        assert result["tool"] == "nmap"
