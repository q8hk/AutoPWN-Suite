from dataclasses import asdict, dataclass
from textwrap import wrap
import json
from pathlib import Path

from modules.logger import banner
from modules.nist_search import Vulnerability, searchCVE
from modules.utils import CheckConnection, get_terminal_width
from rich.progress_bar import ProgressBar


@dataclass
class VulnerableSoftware:
    title: str
    CVEs: list


# Cache file for storing previously fetched CVE results
CACHE_FILE = Path(__file__).resolve().parent / "data" / "cve_cache.json"
keyword_cache = {}


def load_cache() -> None:
    """Load cached CVE results from disk if available."""
    if not CACHE_FILE.exists():
        return
    try:
        with open(CACHE_FILE, "r") as f:
            data = json.load(f)
        for key, cves in data.items():
            keyword_cache[key] = [Vulnerability(**cve) for cve in cves]
    except Exception:
        # Ignore cache loading errors
        pass


def save_cache() -> None:
    """Persist cached CVE results to disk."""
    try:
        CACHE_FILE.parent.mkdir(parents=True, exist_ok=True)
        serializable = {
            key: [asdict(cve) for cve in cves] for key, cves in keyword_cache.items()
        }
        with open(CACHE_FILE, "w") as f:
            json.dump(serializable, f)
    except Exception:
        # Ignore cache saving errors
        pass


load_cache()


def GenerateKeyword(product: str, version: str) -> str:
    if product == "Unknown":
        product = ""

    if version == "Unknown":
        version = ""

    keyword = ""
    dontsearch = [
        "ssh",
        "vnc",
        "http",
        "https",
        "ftp",
        "sftp",
        "smtp",
        "smb",
        "smbv2",
        "linux telnetd",
        "microsoft windows rpc",
        "metasploitable root shell",
        "gnu classpath grmiregistry",
    ]

    if product.lower() not in dontsearch and product != "":
        keyword = f"{product} {version}".rstrip()

    return keyword


def GenerateKeywords(HostArray: list) -> list:
    keywords = []
    for port in HostArray:
        product = str(port[3])
        version = str(port[4])

        keyword = GenerateKeyword(product, version)
        if not keyword == "" and not keyword in keywords:
            keywords.append(keyword)

    return keywords


def SearchKeyword(keyword: str, log, apiKey=None) -> list:
    if keyword in keyword_cache:
        return keyword_cache[keyword]

    try:
        ApiResponseCVE = searchCVE(keyword, log, apiKey)
    except KeyboardInterrupt:
        log.logger("warning", f"Skipped vulnerability detection for {keyword}")
    except Exception as e:
        log.logger("error", e)
    else:
        keyword_cache[keyword] = ApiResponseCVE
        save_cache()
        return ApiResponseCVE

    return []


def SearchSploits(HostArray: list, log, console, console2, apiKey=None) -> list:
    VulnsArray = []
    target = str(HostArray[0][0])
    term_width = get_terminal_width()

    if not CheckConnection(log):
        return []

    keywords = GenerateKeywords(HostArray)

    if len(keywords) == 0:
        log.logger("warning", f"Insufficient information for {target}")
        return []

    log.logger(
        "info", f"Searching vulnerability database for {len(keywords)} keyword(s) ..."
    )

    printed_banner = False
    with console2.status(
        "[white]Searching vulnerabilities ...[/white]", spinner="bouncingBar"
    ) as status:
        for keyword in keywords:
            status.start()
            status.update(
                "[white]Searching vulnerability database for[/white] "
                + f"[red]{keyword}[/red] [white]...[/white]"
            )
            ApiResponseCVE = SearchKeyword(keyword, log, apiKey)
            status.stop()
            if len(ApiResponseCVE) == 0:
                continue

            if not printed_banner:
                banner(f"Possible vulnerabilities for {target}", "red", console)
                printed_banner = True

            console.print(f"┌─ [yellow][ {keyword} ][/yellow]")

            CVEs = []
            for CVE in ApiResponseCVE:
                CVEs.append(CVE.CVEID)
                console.print(f"│\n├─────┤ [red]{CVE.CVEID}[/red]\n│")

                wrapped_description = wrap(CVE.description, term_width - 50)
                console.print(f"│\t\t[cyan]Description: [/cyan]")
                for line in wrapped_description:
                    console.print(f"│\t\t\t{line}")
                console.print(
                    f"│\t\t[cyan]Severity: [/cyan]{CVE.severity} - {CVE.severity_score}\n"
                    + f"│\t\t[cyan]Exploitability: [/cyan] {CVE.exploitability}\n"
                    + f"│\t\t[cyan]Details: [/cyan] {CVE.details_url}"
                )

            VulnObject = VulnerableSoftware(title=keyword, CVEs=CVEs)
            VulnsArray.append(VulnObject)
            console.print("└" + "─" * (term_width - 1))

    return VulnsArray
