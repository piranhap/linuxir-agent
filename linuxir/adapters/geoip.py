"""Best-effort IP geolocation (fully optional; never network-dependent at import time).

Uses the local ``geoiplookup`` CLI if installed. No database / no binary → unavailable
result. The accuracy report flags GeoIP misattribution (DE read as Russia) as a caught
hallucination, so this adapter deliberately returns only what the local DB says, with no
embellishment for the model to over-read.
"""

from __future__ import annotations

from .base import run_binary, summarize


def geoip_lookup(ip: str) -> str:
    res = run_binary(["geoiplookup", ip], timeout=15)
    if not res.get("available", False):
        return (
            f"[tool unavailable] geoiplookup is not installed; cannot geolocate {ip}. "
            "Do not infer a country without data."
        )
    return summarize(res)
