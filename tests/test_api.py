from types import SimpleNamespace

import pytest

from api import AutoScanner


def test_create_scan_args_basic(monkeypatch):
    scanner = AutoScanner()
    args = scanner.CreateScanArgs(100, 3, False, None)
    assert "--host-timeout 100" in args
    assert "-T 3" in args
    assert "-sV" in args


def test_create_scan_args_os_scan_requires_root(monkeypatch):
    scanner = AutoScanner()
    monkeypatch.setattr("api.is_root", lambda: False)
    with pytest.raises(Exception):
        scanner.CreateScanArgs(None, None, True, None)


def test_init_host_info_missing_fields():
    scanner = AutoScanner()
    info = scanner.InitHostInfo({})
    assert info == {
        "mac": "Unknown",
        "vendor": "Unknown",
        "os_name": "Unknown",
        "os_accuracy": "Unknown",
        "os_type": "Unknown",
    }


def test_parse_vuln_info():
    scanner = AutoScanner()
    vuln = SimpleNamespace(
        description="desc",
        severity="high",
        severity_score=9.0,
        details_url="url",
        exploitability="exploit",
    )
    info = scanner.ParseVulnInfo(vuln)
    assert info["description"] == "desc"
    assert info["severity_score"] == 9.0


def test_scan_with_mocks(monkeypatch):
    scanner = AutoScanner()
    # mock PortScanner
    class FakeScanner:
        def scan(self, hosts, arguments):
            pass

        def __getitem__(self, host):
            return {
                "tcp": {80: {"product": "nginx", "version": "1.0"}},
                "addresses": {"mac": "aa"},
                "vendor": ["vendor"],
                "osmatch": [{"name": "Linux", "accuracy": "100", "osclass": [{"type": "os"}]}],
            }

    monkeypatch.setattr("api.PortScanner", lambda: FakeScanner())
    monkeypatch.setattr("api.GenerateKeyword", lambda p, v: "nginx 1.0")

    class FakeVuln(SimpleNamespace):
        CVEID = "CVE-1"

    monkeypatch.setattr("api.searchCVE", lambda keyword, log, api: [FakeVuln(description="d", severity="s", severity_score=1, details_url="u", exploitability="e")])
    result = scanner.scan("127.0.0.1", scan_vulns=True)
    assert "127.0.0.1" in result
    assert result["127.0.0.1"]["ports"][80]["product"] == "nginx"
    assert "nginx" in result["127.0.0.1"]["vulns"]
