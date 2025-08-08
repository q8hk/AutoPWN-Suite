import os
from types import SimpleNamespace

import pytest
from rich.console import Console

from modules import utils
from modules.utils import (
    ScanMode,
    ScanType,
    InitArgsAPI,
    InitArgsScanType,
    InitArgsTarget,
    InitArgsMode,
    InitReport,
    Confirmation,
    UserConfirmation,
    GetHostsToScan,
    SaveOutput,
    get_terminal_width,
)


class DummyLog:
    def __init__(self):
        self.messages = []

    def logger(self, level, message):
        self.messages.append((level, message))


@pytest.fixture
def log():
    return DummyLog()


@pytest.fixture(autouse=True)
def cleanup(tmp_path, monkeypatch):
    # ensure we run in temporary directory for file-based tests
    monkeypatch.chdir(tmp_path)
    yield


def create_args(**kwargs):
    defaults = dict(
        api=None,
        scan_type=None,
        target=None,
        host_file=None,
        mode="normal",
        yes_please=False,
        report=None,
        report_email=None,
        report_email_password=None,
        report_email_to=None,
        report_email_from=None,
        report_email_server=None,
        report_email_server_port=None,
        report_webhook=None,
        speed=3,
        host_timeout=240,
        nmap_flags="",
    )
    defaults.update(kwargs)
    return SimpleNamespace(**defaults)


def test_initargsapi_reads_file(log):
    with open("api.txt", "w", encoding="utf-8") as f:
        f.write("KEY\n")
    args = create_args()
    key = InitArgsAPI(args, log)
    assert key == "KEY"


def test_initargsscantype_arp_when_root(monkeypatch, log):
    args = create_args(scan_type="arp")
    monkeypatch.setattr(utils, "is_root", lambda: True)
    result = InitArgsScanType(args, log)
    assert result is ScanType.ARP


def test_initargsscantype_ping_when_not_root(monkeypatch, log):
    args = create_args(scan_type="arp")
    monkeypatch.setattr(utils, "is_root", lambda: False)
    result = InitArgsScanType(args, log)
    assert result is ScanType.Ping


def test_initargstarget_hostfile(log):
    with open("hosts.txt", "w", encoding="utf-8") as f:
        f.write("1.1.1.1\n2.2.2.2\n")
    args = create_args(host_file="hosts.txt")
    result = InitArgsTarget(args, log)
    assert result == ["1.1.1.1", "2.2.2.2"]


def test_initargsmode_evade_requires_root(monkeypatch, log):
    args = create_args(mode="evade")
    monkeypatch.setattr(utils, "is_root", lambda: False)
    result = InitArgsMode(args, log)
    assert result is ScanMode.Normal


def test_initargsmode_noise(monkeypatch, log):
    args = create_args(mode="noise")
    result = InitArgsMode(args, log)
    assert result is ScanMode.Noise


def test_initreport_email(log):
    args = create_args(
        report="email",
        report_email="user@example.com",
        report_email_password="pw",
        report_email_to="to@example.com",
        report_email_from="from@example.com",
        report_email_server="smtp.example.com",
        report_email_server_port=587,
    )
    method, obj = InitReport(args, log)
    from modules.report import ReportType, ReportMail

    assert method is ReportType.EMAIL
    assert isinstance(obj, ReportMail)
    assert obj.email == "user@example.com"


def test_confirmation_yes(monkeypatch):
    monkeypatch.setattr(utils, "DontAskForConfirmation", False, raising=False)
    monkeypatch.setattr("builtins.input", lambda *args, **kwargs: "y")
    assert Confirmation("?") is True


def test_userconfirmation_auto(monkeypatch):
    monkeypatch.setattr(utils, "DontAskForConfirmation", True, raising=False)
    assert UserConfirmation() == (True, True, True)


def test_gethosts_no_hosts():
    console = Console(record=True)
    with pytest.raises(SystemExit):
        GetHostsToScan([], console)


def test_saveoutput_html(tmp_path):
    console = Console(record=True)
    console.print("test")
    out = tmp_path / "out"
    SaveOutput(console, "html", None, str(out))
    assert os.path.exists(str(out) + ".html")


def test_get_terminal_width():
    width = get_terminal_width()
    assert isinstance(width, int) and width > 0
