import logging

from rich.console import Console

from modules.logger import Logger, banner


def test_banner_prints_without_error():
    console = Console(record=True)
    banner("msg", "red", console)
    assert console.export_text().strip() != ""


def test_logger_levels(monkeypatch):
    console = Console(record=True)
    logger = Logger(console)

    records = []

    def fake_info(msg):
        records.append(msg)

    monkeypatch.setattr(logger.log, "info", fake_info)
    logger.logger("info", "hello")
    assert any("hello" in r for r in records)
