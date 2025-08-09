from types import SimpleNamespace

import pytest

from modules.report import (
    InitializeReport,
    InitializeWebhookReport,
    ReportMail,
    ReportType,
    SendWebhook,
)


class DummyLog:
    def __init__(self):
        self.messages = []

    def logger(self, level, message):
        self.messages.append((level, message))


class DummyConsole:
    def save_text(self, filename):
        with open(filename, "w", encoding="utf-8") as f:
            f.write("log")

    def save_html(self, filename):
        with open(filename, "w", encoding="utf-8") as f:
            f.write("<html></html>")


def test_initialize_report_calls_email(monkeypatch):
    called = {}

    def fake_email(obj, log, console):
        called["email"] = True

    monkeypatch.setattr("modules.report.InitializeEmailReport", fake_email)
    log = DummyLog()
    console = DummyConsole()
    email_obj = ReportMail("a", "b", "c", "d", "e", 1)
    InitializeReport(ReportType.EMAIL, email_obj, log, console)
    assert called.get("email")


def test_send_webhook_success(monkeypatch, tmp_path):
    class Resp:
        status_code = 200

    def fake_post(url, files):
        return Resp()

    monkeypatch.setattr("modules.report.post", fake_post)
    log = DummyLog()
    (tmp_path / "report.log").write_text("data")
    monkeypatch.chdir(tmp_path)
    SendWebhook("http://example.com", log)
    assert ("success", "Webhook report sent succesfully.") in log.messages
