class WebTest:
    """Interface for web vulnerability plugins."""

    def __init__(self, log, console) -> None:
        self.log = log
        self.console = console

    def run(self, url):
        raise NotImplementedError
