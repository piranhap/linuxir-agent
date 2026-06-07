"""Volatility3 memory-analysis wrappers (graceful fallback when vol3 is absent).

Volatility3 does not require a pre-built profile — it resolves the kernel from the image —
so the common "no profile detected" failure of vol2 does not apply. If detection still
fails, callers can pass ``--os-name linux`` via ``extra``. When ``vol``/``vol3`` is not
installed, :func:`run_binary` returns an unavailable result and the agent reasons about
the gap instead of crashing.
"""

from __future__ import annotations

import shutil

from .base import run_binary, summarize


def _vol_binary() -> str | None:
    for name in ("vol", "vol3", "volatility3", "volatility"):
        if shutil.which(name):
            return name
    return None


def _run_plugin(memory_image: str, plugin: str, extra: list[str] | None = None) -> str:
    binary = _vol_binary()
    if binary is None:
        return (
            "[tool unavailable] volatility3 (vol/vol3) is not installed on this host. "
            "Install with `pip install volatility3` to enable memory analysis."
        )
    argv = [binary, "-f", memory_image, *(extra or []), plugin]
    return summarize(run_binary(argv, timeout=300))


def pslist(memory_image: str, extra: list[str] | None = None) -> str:
    return _run_plugin(memory_image, "linux.pslist.PsList", extra)


def pstree(memory_image: str, extra: list[str] | None = None) -> str:
    return _run_plugin(memory_image, "linux.pstree.PsTree", extra)


def malfind(memory_image: str, extra: list[str] | None = None) -> str:
    return _run_plugin(memory_image, "linux.malfind.Malfind", extra)


def netstat(memory_image: str, extra: list[str] | None = None) -> str:
    return _run_plugin(memory_image, "linux.sockstat.Sockstat", extra)
