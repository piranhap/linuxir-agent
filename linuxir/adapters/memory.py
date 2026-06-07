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


def bash(memory_image: str, extra: list[str] | None = None) -> str:
    return _run_plugin(memory_image, "linux.bash.Bash", extra)


def check_modules(memory_image: str, extra: list[str] | None = None) -> str:
    return _run_plugin(memory_image, "linux.check_modules.Check_modules", extra)


def lsmod(memory_image: str, extra: list[str] | None = None) -> str:
    return _run_plugin(memory_image, "linux.lsmod.Lsmod", extra)


def cmdline(memory_image: str, extra: list[str] | None = None) -> str:
    return _run_plugin(memory_image, "linux.cmdline.Cmdline", extra)


def kernel_banner(memory_image: str, extra: list[str] | None = None) -> str:
    """Tier-2 profile detection: recover the 'Linux version ...' banner from the image.

    Volatility3 normally resolves the kernel itself (tier 1). When auto-detection fails,
    the kernel banner string in the image tells you exactly which kernel/distro symbols are
    needed (tier 2 -> match to a profile, tier 3). This uses `grep -a` so it works even
    when vol3 is absent, and degrades gracefully if `grep` is missing.
    """
    res = run_binary(["grep", "-a", "-m", "5", "-o", "Linux version [^\\\\]*", memory_image])
    if not res.get("available"):
        return summarize(res)
    out = (res.get("stdout") or "").strip()
    if not out:
        return ("[no 'Linux version' banner found in image] — auto-detection may still work; "
                "if vol3 fails, supply symbols matching the source kernel manually.")
    return ("[recovered kernel banner(s) — use to select vol3 symbols if auto-detect fails]\n"
            + out)
