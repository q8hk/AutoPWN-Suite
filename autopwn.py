from __future__ import annotations

from argparse import Namespace
from concurrent.futures import Future, ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from datetime import datetime
from typing import Dict, List, Union

from rich.console import Console

from modules.banners import print_banner
from modules.getexploits import GetExploitsFromArray
from modules.logger import Logger
from modules.report import InitializeReport
from modules.scanner import AnalyseScanResults, DiscoverHosts, NoiseScan, PortScan
from modules.searchvuln import SearchSploits
from modules.utils import (
    Confirmation,
    GetHostsToScan,
    InitArgsAPI,
    InitArgsConf,
    InitArgsMode,
    InitArgsScanType,
    InitArgsTarget,
    InitAutomation,
    InitReport,
    ParamPrint,
    SaveOutput,
    ScanMode,
    ScanType,
    WebScan,
    check_nmap,
    check_version,
    cli,
)
from modules.version import FORK_MAINTAINER, ORIGINAL_AUTHOR, __version__
from modules.web.webvuln import webvuln


@dataclass(frozen=True)
class ScanConfiguration:
    """Defines which scanning components are enabled for this run."""

    scan_ports: bool
    scan_vulns: bool
    download_exploits: bool
    scan_web: bool


def resolve_targets(
    args: Namespace,
    target_argument: Union[str, List[str]],
    scantype: ScanType,
    scanmode: ScanMode,
    console: Console,
) -> List[str]:
    """Resolve the list of targets based on discovery settings."""

    if args.skip_discovery:
        return target_argument if isinstance(target_argument, list) else [target_argument]

    hosts = DiscoverHosts(target_argument, console, scantype, scanmode)
    return GetHostsToScan(hosts, console)


def determine_scan_configuration(args: Namespace, log: Logger) -> ScanConfiguration:
    """Determine which scanning phases should run for this invocation."""

    scan_ports = args.scan_ports if args.scan_ports is not None else Confirmation(
        "Do you want to scan ports? [Y/n] : "
    )

    if not scan_ports:
        if args.scan_vulns and not args.scan_ports:
            log.logger(
                "warning",
                "Vulnerability scanning requested but port scanning disabled. Skipping.",
            )
        if args.download_exploits and not args.scan_ports:
            log.logger(
                "warning",
                "Exploit downloads requested but port scanning disabled. Skipping.",
            )
        scan_vulns = False
        download_exploits = False
    else:
        scan_vulns = (
            args.scan_vulns
            if args.scan_vulns is not None
            else Confirmation("Do you want to scan for vulnerabilities? [Y/n] : ")
        )
        if not scan_vulns:
            if args.download_exploits:
                log.logger(
                    "warning",
                    "Exploit downloads requested but vulnerability scanning disabled. Skipping.",
                )
            download_exploits = False
        else:
            download_exploits = (
                args.download_exploits
                if args.download_exploits is not None
                else Confirmation("Do you want to download exploits? [Y/n] : ")
            )

    scan_web = (
        args.scan_web
        if args.scan_web is not None
        else WebScan()
    )

    return ScanConfiguration(scan_ports, scan_vulns, download_exploits, scan_web)


def sanitize_thread_count(requested_threads: int, log: Logger) -> int:
    """Ensure thread count is a positive integer."""

    if requested_threads <= 0:
        log.logger(
            "warning",
            f"Invalid thread count '{requested_threads}'. Falling back to a single worker thread.",
        )
        return 1
    return requested_threads


def _perform_port_workflow(
    host: str,
    config: ScanConfiguration,
    log: Logger,
    console: Console,
    console2: Console,
    api_key: str | None,
    scanmode: ScanMode,
    scanspeed: int,
    host_timeout: int,
    nmap_flags: str,
) -> None:
    """Run the full port/vulnerability workflow for a single host."""

    # Port scanning
    try:
        port_scan_results = PortScan(host, log, scanspeed, host_timeout, scanmode, nmap_flags)
    except KeyboardInterrupt:
        raise
    except SystemExit as exc:
        log.logger("error", f"Port scanning failed for {host}: {exc}")
        return
    except Exception as exc:  # noqa: BLE001
        log.logger("error", f"Unexpected error while scanning ports on {host}: {exc}")
        return

    # Discovery of services and result analysis
    try:
        port_array = AnalyseScanResults(port_scan_results, log, console, host)
    except KeyboardInterrupt:
        raise
    except SystemExit as exc:
        log.logger("error", f"Port analysis failed for {host}: {exc}")
        return
    except Exception as exc:  # noqa: BLE001
        log.logger("error", f"Failed to analyse port scan results for {host}: {exc}")
        return

    if not config.scan_vulns or not port_array:
        return

    # Vulnerability enumeration
    try:
        vuln_array = SearchSploits(port_array, log, console, console2, api_key)
    except KeyboardInterrupt:
        raise
    except SystemExit as exc:
        log.logger("error", f"Vulnerability lookup aborted for {host}: {exc}")
        return
    except Exception as exc:  # noqa: BLE001
        log.logger("error", f"Vulnerability lookup failed for {host}: {exc}")
        return

    if not config.download_exploits or not vuln_array:
        return

    # Exploit retrieval
    try:
        GetExploitsFromArray(vuln_array, log, console, console2, host)
    except KeyboardInterrupt:
        raise
    except SystemExit as exc:
        log.logger("error", f"Exploit download aborted for {host}: {exc}")
    except Exception as exc:  # noqa: BLE001
        log.logger("error", f"Exploit download failed for {host}: {exc}")


def _perform_web_scan(host: str, log: Logger, console: Console) -> None:
    """Run the web vulnerability scanner for a single host."""

    try:
        webvuln(host, log, console)
    except KeyboardInterrupt:
        raise
    except SystemExit as exc:
        log.logger("error", f"Web vulnerability scanning aborted for {host}: {exc}")
    except Exception as exc:  # noqa: BLE001
        log.logger("error", f"Web vulnerability scanning failed for {host}: {exc}")


def StartScanning(
    args: Namespace,
    targetarg: Union[str, List[str]],
    scantype: ScanType,
    scanmode: ScanMode,
    api_key: str | None,
    console: Console,
    console2: Console,
    log: Logger,
) -> None:
    """Coordinate the scanning workflow for the selected targets."""

    check_nmap(log)

    if scanmode == ScanMode.Noise:
        log.logger(
            "info",
            "Noise mode selected. Generating noise and exiting without additional scans.",
        )
        try:
            NoiseScan(targetarg, log, console, scantype, args.noise_timeout)
        except SystemExit:
            console.print("Noise mode completed. Exiting as requested.")
            raise
        return

    # Host discovery and target selection
    targets = resolve_targets(args, targetarg, scantype, scanmode, console)

    # Decide which scan components to execute
    config = determine_scan_configuration(args, log)

    # Prepare concurrency settings
    thread_count = sanitize_thread_count(args.threads, log)

    if not config.scan_ports and not config.scan_web:
        log.logger("warning", "All scanning components disabled. Nothing to do.")
        return

    with ThreadPoolExecutor(max_workers=thread_count) as executor:
        future_descriptions: Dict[Future[None], str] = {}
        for host in targets:
            if config.scan_ports:
                future_descriptions[
                    executor.submit(
                        _perform_port_workflow,
                        host,
                        config,
                        log,
                        console,
                        console2,
                        api_key,
                        scanmode,
                        args.speed,
                        args.host_timeout,
                        args.nmap_flags,
                    )
                ] = f"port workflow for {host}"
            if config.scan_web:
                future_descriptions[
                    executor.submit(_perform_web_scan, host, log, console)
                ] = f"web scan for {host}"

        for future in as_completed(future_descriptions):
            description = future_descriptions[future]
            try:
                future.result()
            except KeyboardInterrupt:
                raise
            except SystemExit as exc:
                log.logger("error", f"Unhandled exit during {description}: {exc}")
            except Exception as exc:  # noqa: BLE001
                log.logger("error", f"Unhandled error during {description}: {exc}")

    console.print(
        "{time} - Scan completed.".format(
            time=datetime.now().strftime("%b %d %Y %H:%M:%S")
        )
    )


def main() -> None:
    """Entry point for the AutoPWN Suite CLI."""

    args = cli()
    if args.no_color:
        console = Console(record=True, color_system=None)
        console2 = Console(record=False, color_system=None)
    else:
        console = Console(record=True, color_system="truecolor")
        console2 = Console(record=False, color_system="truecolor")
    log = Logger(console)

    if args.version:
        print(
            f"AutoPWN Suite v{__version__} (original author: {ORIGINAL_AUTHOR}, "
            f"fork maintainer: {FORK_MAINTAINER})"
        )
        raise SystemExit

    print_banner(console)
    check_version(__version__, log)

    if args.config:
        InitArgsConf(args, log)

    InitAutomation(args)
    targetarg = InitArgsTarget(args, log)
    scantype = InitArgsScanType(args, log)
    scanmode = InitArgsMode(args, log)
    api_key = InitArgsAPI(args, log)
    report_method, report_object = InitReport(args, log)

    ParamPrint(args, targetarg, scantype, scanmode, api_key, console, log)

    StartScanning(args, targetarg, scantype, scanmode, api_key, console, console2, log)

    InitializeReport(report_method, report_object, log, console)
    SaveOutput(console, args.output_type, args.report, args.output)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        raise SystemExit("Ctrl+C pressed. Exiting.")
