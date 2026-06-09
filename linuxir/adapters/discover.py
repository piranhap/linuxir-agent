"""Collection-aware artifact discovery.

The typed adapters were first written for a *mounted disk image* — fixed relative paths like
``var/log/auth.log`` or ``home/<user>/.bash_history``. Real IR collections (CylR, UAC,
Velociraptor, KAPE-style triage) instead ship a per-host tree such as
``<host>/syslog.log`` and ``<host>/bash_history/<user>.bash_history``. This helper finds
artifacts by **basename pattern anywhere under the evidence scope** so the same tools work on
both shapes. The walk is bounded (entry cap) so pointing it at a huge mounted filesystem
degrades gracefully rather than hanging.
"""

from __future__ import annotations

import fnmatch
import os
from pathlib import Path


def discover(roots, patterns: tuple[str, ...], *, cap: int = 300_000,
             max_hits: int = 5_000) -> list[Path]:
    """Return files under ``roots`` whose basename matches any glob in ``patterns``.

    Bounded by ``cap`` directory-entries scanned and ``max_hits`` results.
    """
    seen: dict[str, Path] = {}
    scanned = 0
    for root in roots:
        root = Path(root)
        if root.is_file():
            if any(fnmatch.fnmatch(root.name, p) for p in patterns):
                seen[str(root)] = root
            continue
        for dirpath, _dirs, files in os.walk(root, followlinks=False):
            for fn in files:
                scanned += 1
                if scanned > cap or len(seen) >= max_hits:
                    return sorted(seen.values(), key=lambda p: str(p))
                if any(fnmatch.fnmatch(fn, p) for p in patterns):
                    full = Path(dirpath) / fn
                    seen[str(full)] = full
    return sorted(seen.values(), key=lambda p: str(p))
