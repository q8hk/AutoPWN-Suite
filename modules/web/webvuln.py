from modules.logger import banner
from modules.random_user_agent import random_user_agent
from modules.web.crawler import crawl
from modules.web.dirbust import dirbust
import importlib
import pkgutil
from modules.web import plugins
from modules.web.plugins import WebTest
from requests import get
from requests import packages


packages.urllib3.disable_warnings()


def webvuln(target, log, console) -> None:
    """
    Test for web vulnerabilities
    """


    tests = []
    for _, module_name, _ in pkgutil.iter_modules(plugins.__path__):
        importlib.import_module(f'{plugins.__name__}.{module_name}')
    for cls in WebTest.__subclasses__():
        tests.append(cls(log, console))
    def get_url(target):
        """
        Get the target url
        """
        headers = {"User-Agent": next(random_user_agent(log))}
        url_ = [f"http://{target}/", f"https://{target}/"]
        for url in url_:
            try:
                get(url, headers=headers, timeout=10, verify=False)
            except Exception as e:
                continue
            else:
                return url
        return None

    target_url = get_url(target)

    if target_url is None:
        return

    urls = crawl(target_url, log)
    tested_urls, testable_urls = [], []
    for url in urls:
        if "?" in url:
            testable_urls.append(url)

    log.logger("info", f"Found {len(testable_urls)} testable urls.")

    if len(testable_urls) == 0:
        return

    banner(f"Testing web application on {target} ...", "purple", console)

    dirbust(target_url, console, log, timeout=10)

    for url in testable_urls:
        for test in tests:
            test.run(url)
        tested_urls.append(url)
