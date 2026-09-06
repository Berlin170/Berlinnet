"""TP-Link and ZTE adapters.

Both are real detection implementations. Neither claims a blocking capability
it has not confirmed, and both leave the mechanism-specific request shapes to
be filled in against an actual device, because TP-Link in particular ships at
least four incompatible web stacks (legacy /userRpm, the Archer JSON API, the
Deco/Omada cloud API, and the newer /cgi-bin/luci endpoints) and guessing which
one is in front of you produces a Block button that lies.

The honest behaviour until then: detect and identify the router, report that
blocking is not supported, and point the user at the alternatives.
"""

from __future__ import annotations

import re

import httpx

from .base import (
    AuthState, BlockMethod, Capabilities, RouterAdapter, RouterInfo,
    GENERIC_ALTERNATIVES, NO_BLOCKING_MESSAGE,
)


class _WebRouterAdapter(RouterAdapter):
    """Shared HTTP fingerprinting for web-UI routers."""

    #: Paths whose presence identifies the firmware family.
    probe_paths: tuple[str, ...] = ()

    def __init__(self, info: RouterInfo) -> None:
        super().__init__(info)
        self.base = f"http://{info.ip}"
        self._auth_state = AuthState.UNKNOWN

    def _probe(self) -> list[str]:
        """Which of the known paths exist. 401 counts as existing."""
        found: list[str] = []
        try:
            with httpx.Client(base_url=self.base, timeout=5.0) as client:
                for path in self.probe_paths:
                    try:
                        response = client.get(path)
                    except httpx.HTTPError:
                        continue
                    if response.status_code in (200, 401, 403):
                        found.append(f"{path} -> {response.status_code}")
        except httpx.HTTPError:
            pass
        return found

    def probe_capabilities(self) -> Capabilities:
        probed = self._probe() or ["No known management paths responded"]
        return Capabilities(
            can_block=False,
            method=BlockMethod.NONE,
            can_list_clients=False,
            requires_auth=True,
            auth_state=self._auth_state,
            unsupported_reason=(
                NO_BLOCKING_MESSAGE + f" This app recognises the router as "
                f"{self.vendor}, but no blocking mechanism has been implemented and "
                f"verified for this firmware, so it will not pretend to have one."
            ),
            alternatives=GENERIC_ALTERNATIVES,
            probed=probed,
        )


class TPLinkAdapter(_WebRouterAdapter):
    name = "tplink"
    vendor = "TP-Link"
    probe_paths = ("/userRpm/LoginRpm.htm", "/cgi-bin/luci", "/webpages/login.html", "/")

    @classmethod
    def detect(cls, info: RouterInfo) -> int:
        score = 0
        vendor = (info.vendor or "").lower()
        model = (info.model or "").lower()
        if "tp-link" in vendor or "tplink" in vendor:
            score += 60
        if re.search(r"\b(archer|deco|tl-wr|tl-wa|tl-mr)\b", model):
            score += 40
        return min(score, 100)


class ZTEAdapter(_WebRouterAdapter):
    name = "zte"
    vendor = "ZTE"
    probe_paths = ("/webFac", "/common_page/login.gch", "/start.ghtml", "/")

    @classmethod
    def detect(cls, info: RouterInfo) -> int:
        score = 0
        vendor = (info.vendor or "").lower()
        model = (info.model or "").lower()
        server = (info.http_server or "").lower()
        if "zte" in vendor:
            score += 60
        if re.search(r"\b(zxhn|f\d{3}|h\d{3})\b", model):
            score += 40
        if "gch" in server:
            score += 20
        return min(score, 100)
