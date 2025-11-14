"""Version metadata for the AutoPWN Suite fork maintained by q8hk."""

from __future__ import annotations

UPSTREAM_VERSION: str = "2.1.5"
FORK_MAINTAINER: str = "q8hk"
ORIGINAL_AUTHOR: str = "GamehunterKaan"

# NOTE: The forked version keeps the upstream version number and appends a
# fork-specific suffix so the provenance of builds is immediately clear.
__version__: str = f"{UPSTREAM_VERSION}-{FORK_MAINTAINER}.1"

__all__ = [
    "UPSTREAM_VERSION",
    "FORK_MAINTAINER",
    "ORIGINAL_AUTHOR",
    "__version__",
]
