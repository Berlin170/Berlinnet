"""Huawei EchoLife HG8xxx / EchoLife ONT adapter.

These boxes run a Boa 0.94 web server and serve their UI from /cgi-bin/*.asp.
The login contract implemented here was read off the device's own login page
(the form fields and the client-side script that fills them), not guessed:

    POST /cgi-bin/index2.asp
      Username, Password, Password1, Password2, Logoff, hLoginTimes,
      hLoginTimes_Zero, value_one, logintype, Language_Flag
    Cookie: SESSIONID=boasid..., UID=<user>, PSW=<password>

Note the box sends credentials in the clear over HTTP - that is the firmware's
design and there is no HTTPS listener to switch to. The app therefore refuses
to talk to it over anything but a private LAN address, and never logs the
password.

What this adapter deliberately does NOT do:
  * guess or brute-force the password;
  * exploit any of the well-known bugs in this firmware family;
  * claim a blocking capability it has not confirmed exists.

ISP-provisioned units are commonly locked down: the ISP keeps the superadmin
account and the end-user account sees a cut-down menu with no filtering pages
at all. When that is the case, probe_capabilities() reports no blocking.
"""

from __future__ import annotations

import ipaddress
import re
from typing import Optional
from urllib.parse import urljoin

import httpx

from ..credentials import RouterCredentials
from .base import (
    ActionResult, AuthState, BlockMethod, Capabilities, RouterAdapter, RouterInfo,
    NO_BLOCKING_MESSAGE,
)

LOGIN_PATH = "/cgi-bin/index2.asp"
MAIN_PATH = "/cgi-bin/content.asp"
MENU_JS = "/JS/menu.js"

# Verified against a live HG8547M (Boa 0.94). The feature pages are gated on a
# Referer that points back at the frameset - without it Boa answers 401 - and
# the menu that names the real page URLs lives in a JS file, not in content.asp,
# so plain link-crawling finds nothing. The MAC-filter pages use hyphens
# (sec-macfilter.asp) while the list sub-frame uses an underscore
# (sec_macfilterlist.cgi); do not "normalise" these.
MACFILTER_PATH = "/cgi-bin/sec-macfilter.asp"          # list + mode + delete form
MACFILTER_ADD_PATH = "/cgi-bin/sec-addmacfilter.asp"   # add form (POST target)
MACFILTER_LIST_CGI = "/cgi-bin/sec_macfilterlist.cgi"  # entries, rendered in JS

# The menu is a list of MenuNodeConstruction(level, label, "/cgi-bin/x.asp", "").
_MENU_NODE = re.compile(
    r"""MenuNodeConstruction\s*\(\s*\d+\s*,\s*[^,]+,\s*["']([^"']+)["']""", re.IGNORECASE
)
# Filter rows are emitted as stMacFilter(domain, Name, MACAddress, Enable) calls.
_ST_MACFILTER = re.compile(
    r"""stMacFilter\s*\(\s*(['"])(.*?)\1\s*,\s*(['"])(.*?)\3\s*,\s*(['"])(.*?)\5\s*,\s*(['"])(.*?)\7\s*\)""",
    re.IGNORECASE | re.DOTALL,
)

_TITLE = re.compile(r"RES_TITLE_NAME\s*=\s*[\"\']([^\"\']+)[\"\']")
_LINKS = re.compile(r"""(?:src|href|location(?:\.href)?\s*=|url\s*:)\s*=?\s*["\']([^"\']*\.(?:asp|cgi|html))["\']""", re.IGNORECASE)
_FORM_ACTION = re.compile(r"""<form\b[^>]*\baction\s*=\s*["\']([^"\']+)["\']""", re.IGNORECASE)
_INPUT_NAME = re.compile(r"""<(?:input|select)\b[^>]*\bname\s*=\s*["\']([^"\']+)["\']""", re.IGNORECASE)
_MAC_IN_TEXT = re.compile(r"\b([0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5})\b")
# A per-page login challenge is rendered as either an input value or button
# text, depending on the installed firmware. Attribute order is not stable.
_GEN_RANDOM_TAG = re.compile(
    r"<(?:input|button)\b[^>]*\b(?:id|name)\s*=\s*[\"']GenRandom[\"'][^>]*>(?:\s*([^<\s]+)\s*</button>)?",
    re.IGNORECASE,
)
_VALUE_ATTR = re.compile(r"\bvalue\s*=\s*[\"']([^\"']+)[\"']", re.IGNORECASE)
# Invocations, not the function definitions - the argument must be a digit.
_LOGGED_CALL = re.compile(r"userlogin\s*\(\s*(\d)\s*\)")
_PSWST_CALL = re.compile(r"userPSWST\s*\(\s*(\d)\s*\)")

# The MAC-filter feature spans two pages on this firmware: a list page
# (sec_macfilter.asp) that has no editable MAC field, and an "add" sub-page
# (sec_addmacfilter.asp) that carries the actual form. Driving the list page
# is why blocking silently did nothing; the input we need is only on the add
# page. Match links to it by name so we post to the right place.
_ADD_LINK = re.compile(
    r"""["']([^"']*add[^"']*(?:mac)?[^"']*filter[^"']*\.(?:asp|cgi)[^"']*)["']""",
    re.IGNORECASE,
)

# Boa builds guard state-changing posts with a per-page anti-CSRF token. It is
# rendered as a hidden input whose name is one of these; it must be echoed back
# or the CGI drops the request. Attribute order is not stable, so this only
# locates the tag - the value is pulled out of it separately.
_TOKEN_TAG = re.compile(
    r"<input\b[^>]*\bname\s*=\s*[\"'](?:x\.)?(X_HW_Token|onttoken|csrftoken|csrf_token)[\"'][^>]*>",
    re.IGNORECASE,
)

# The "check code" the router shows next to the add form is not a server-side
# CAPTCHA. Its login page defines getRandomLetterNum(6) and generates the code
# in the browser with Math.random().toString(36); the value is only compared
# client-side before submit. So a self-generated code of the same shape is
# accepted. We mirror the router's own generator rather than hardcode a string.
_CHECKCODE_FIELD_HINTS = ("random", "checkcode", "check_code", "verifycode", "vercode", "captcha")

# Which filtering direction the list page is currently in. Adding a MAC only
# denies it in blacklist mode; in whitelist mode the same action would *allow*
# it and deny everyone else, so we must know the mode before claiming a block.
_WHITELIST_CHECKED = re.compile(
    r"<input\b[^>]*\bvalue\s*=\s*[\"']?(?:1|white(?:list)?)[\"']?[^>]*\bchecked\b|"
    r"<input\b[^>]*\bchecked\b[^>]*\bvalue\s*=\s*[\"']?(?:1|white(?:list)?)[\"']?",
    re.IGNORECASE,
)

# Page-name fragments that indicate a real blocking mechanism.
_BLOCK_PAGE_HINTS: list[tuple[tuple[str, ...], BlockMethod]] = [
    (("macfilter", "mac_filter", "filtermac"), BlockMethod.MAC_FILTER),
    (("wlanfilter", "wlanacl", "wlanaccess"), BlockMethod.WLAN_CONTROL),
    (("aclservice", "acl"), BlockMethod.ACCESS_CONTROL),
    (("firewall", "attackfilter"), BlockMethod.FIREWALL_RULE),
    (("parentcontrol", "parental", "timerule"), BlockMethod.PARENTAL_CONTROL),
]

HUAWEI_ALTERNATIVES = [
    "Open the router UI directly and look under Security or Forward Rules for a "
    "MAC Filter page. ISP-locked units often hide it from the normal user account.",
    "Ask your ISP for the superadmin account for this ONT, or ask them to enable "
    "MAC filtering on it. Some ISPs will do this on request.",
    "Put your own router (ideally OpenWrt-compatible) behind the ONT and let it "
    "run the LAN. This app can then block clients through that router.",
    "Change the Wi-Fi password and reconnect only the devices you recognise. This "
    "is the one action that reliably removes an unwanted device from an ONT you "
    "do not fully control.",
    "If a device routes through this PC, block it with a Windows Firewall rule.",
]


def _is_private(host: str) -> bool:
    try:
        return ipaddress.ip_address(host).is_private
    except ValueError:
        return False


class HuaweiAdapter(RouterAdapter):
    name = "huawei"
    vendor = "Huawei"

    def __init__(self, info: RouterInfo) -> None:
        super().__init__(info)
        self.base = f"http://{info.ip}"
        self._client: Optional[httpx.Client] = None
        self._pages: dict[str, str] = {}      # path -> page body
        self._block_page: Optional[str] = None   # list page (sec_macfilter.asp)
        self._add_page: Optional[str] = None     # add form (sec_addmacfilter.asp)
        self._block_method = BlockMethod.NONE
        self._auth_state = AuthState.UNKNOWN

    # -------------------------------------------------------------- detection

    @classmethod
    def detect(cls, info: RouterInfo) -> int:
        score = 0
        server = (info.http_server or "").lower()
        model = (info.model or "").lower()
        vendor = (info.vendor or "").lower()

        if "huawei" in vendor:
            score += 45
        if re.search(r"\bhg\d{3,4}", model) or "echolife" in model:
            score += 45
        if "boa/" in server:
            # Boa alone is weak evidence - other embedded devices use it too.
            score += 20
        if 7547 in (info.open_ports or []):
            score += 5
        return min(score, 100)

    # -------------------------------------------------------------- http glue

    def _http(self) -> httpx.Client:
        if self._client is None:
            self._client = httpx.Client(
                base_url=self.base,
                timeout=httpx.Timeout(10.0),
                follow_redirects=True,
                headers={"User-Agent": "LAN-Device-Manager/1.0"},
            )
        return self._client

    @staticmethod
    def _decode(response: httpx.Response) -> str:
        """These pages declare gb2312; be forgiving about it."""
        try:
            return response.content.decode("gb2312", errors="replace")
        except LookupError:
            return response.text

    def _get(self, path: str, referer: str = MAIN_PATH) -> Optional[str]:
        # Feature pages 401 unless the request carries a Referer pointing back at
        # the frameset; the login and menu assets do not care, so a default of
        # content.asp is safe everywhere.
        headers = {"Referer": urljoin(self.base, referer)} if referer else {}
        try:
            response = self._http().get(path, headers=headers)
        except httpx.HTTPError:
            return None
        if response.status_code != 200:
            return None
        return self._decode(response)

    def _post_form(self, path: str, data: dict, referer: str) -> Optional[httpx.Response]:
        """POST a urlencoded form with the Referer this firmware insists on."""
        try:
            return self._http().post(
                path, data=data,
                headers={"Content-Type": "application/x-www-form-urlencoded",
                         "Referer": urljoin(self.base, referer)},
            )
        except httpx.HTTPError:
            return None

    @staticmethod
    def _login_challenge(login_page: str) -> Optional[str]:
        """Read the one-time code displayed by the normal login page."""
        match = _GEN_RANDOM_TAG.search(login_page)
        if not match:
            return None
        value = _VALUE_ATTR.search(match.group(0))
        if value:
            return value.group(1).strip()
        text = match.group(1)
        return text.strip() if text else None

    @staticmethod
    def _check_code(length: int = 6) -> str:
        """Reproduce the router's own getRandomLetterNum(length).

        The page's script builds the code with Math.random().toString(36) and
        slices it to `length`; base-36 is 0-9a-z. The value is only ever checked
        in the browser, so a code of this shape is all the CGI needs to see.
        """
        import random
        import string

        alphabet = string.digits + string.ascii_lowercase   # base-36, as toString(36)
        return "".join(random.choice(alphabet) for _ in range(length))

    @staticmethod
    def _new_session_id() -> str:
        """Reproduce the login page's createNewSessionID(): 'boasid' + 8 hex.

        The browser makes its own session id and cookies it before posting; the
        router validates the shape, not a value it issued. Example: boasid3e0e965b.
        """
        import random

        return "boasid" + "".join(random.choice("0123456789abcdef") for _ in range(8))

    @staticmethod
    def _named_input_value(body: str, tag_re: re.Pattern) -> Optional[str]:
        """Value of the first <input> whose tag `tag_re` matches (order-tolerant)."""
        tag = tag_re.search(body)
        if not tag:
            return None
        value = _VALUE_ATTR.search(tag.group(0))
        return value.group(1) if value else ""

    def _resolve_target(self, base_path: str, action: str) -> str:
        """Absolute path for a form action found on `base_path`."""
        if not action:
            return base_path
        if action.startswith("/"):
            return action
        return urljoin(base_path, action)

    # ------------------------------------------------------------------ auth

    def authenticate(self, credentials: RouterCredentials) -> ActionResult:
        if not _is_private(self.info.ip):
            return ActionResult(
                False,
                "Refusing to send credentials to a non-private address. This app "
                "only talks to routers on your own LAN.",
            )

        client = self._http()
        # Pick up the session cookie the way a browser would.
        try:
            login_response = client.get(LOGIN_PATH)
        except httpx.HTTPError as exc:
            return ActionResult(False, f"Could not reach the router: {exc.__class__.__name__}")

        # The login "check code" is generated in the browser, not by the server:
        # GenRandom ships with value="" and btnRandomGen() fills it via
        # getRandomLetterNum(6) only on click, then randomCodeCheck() merely
        # compares GenRandom to what the user typed. The server never validates
        # it. So we generate our own code and post it in both fields, exactly as
        # clicking the button and typing the same value would. (Reading it off
        # the page, as before, found only the empty value and wrongly bailed.)
        check_code = self._login_challenge(self._decode(login_response)) or self._check_code()

        # The session id is generated by the CLIENT, not the server: the login
        # page's createNewSessionID() builds "boasid" + 8 hex chars and sets it
        # as a cookie before submitting. The router never Set-Cookies one, so the
        # old code (reading SESSIONID off the server) sent none and login failed.
        session_id = client.cookies.get("SESSIONID") or self._new_session_id()
        form = {
            "Username": credentials.username,
            "Password": credentials.password,
            "Password1": credentials.password,
            "Password2": credentials.password,
            "Logoff": "0",
            "hLoginTimes": "1",
            "hLoginTimes_Zero": "0",
            "value_one": "1",
            "logintype": "usr",
            "Language_Flag": "0",
            "GenRandom": check_code,
            "RandomNumb": check_code,
        }
        # Set cookies WITHOUT a domain. httpx's cookie jar mishandles an
        # IP-address domain and then silently omits the cookie from the request,
        # so a domain-pinned SESSIONID/UID/PSW never reaches the box and login
        # fails even with correct credentials. Domainless cookies are associated
        # with the request host and sent as a browser would send them.
        client.cookies.set("UID", credentials.username)
        client.cookies.set("PSW", credentials.password)
        client.cookies.set("LoginTimes", "1")
        client.cookies.set("SESSIONID", session_id)

        try:
            response = client.post(
                LOGIN_PATH, data=form,
                headers={"Content-Type": "application/x-www-form-urlencoded",
                         "Referer": urljoin(self.base, LOGIN_PATH)},
            )
        except httpx.HTTPError as exc:
            return ActionResult(False, f"Login request failed: {exc.__class__.__name__}")
        # NB: the PSW cookie IS the session on this box - every authenticated
        # request must carry it, so we keep it in the jar for the life of the
        # session and only clear it in logout(). Deleting it here (as an earlier
        # version did) logged us straight back out, so the next content.asp read
        # bounced to the login page and the whole thing looked like a bad
        # password.

        body = self._decode(response)

        # On a POST the box reports its verdict by emitting calls to the page's
        # own state setters - userlogin(N) and userPSWST(N). A plain GET of the
        # login page contains neither, only their definitions, so matching the
        # invocation (a digit argument) is what distinguishes the two.
        logged = _LOGGED_CALL.search(body)
        if logged and logged.group(1) in ("1", "2"):
            self._auth_state = AuthState.FAILED
            who = "An administrator" if logged.group(1) == "1" else "A user"
            return ActionResult(
                False,
                f"{who} session is already open on this router. Log out of the "
                "router's web page in your browser, or wait for the session to "
                "time out, then try again.",
            )

        # Authoritative check: the main frame is only served to a live session.
        main = self._get(MAIN_PATH)
        if main is None or "index2.asp" in (main or "")[:400]:
            self._auth_state = AuthState.FAILED
            pswst = _PSWST_CALL.search(body)
            if pswst and pswst.group(1) == "2":
                return ActionResult(
                    False,
                    "The router accepted the account but wants the password changed "
                    "before it will allow a session. Sign in with a browser once to "
                    "clear that, then try again here.",
                )
            return ActionResult(
                False,
                "The router rejected those credentials. Check the username and "
                "password printed on the label, or the ones your ISP gave you.",
            )

        self.credentials = credentials
        self._auth_state = AuthState.AUTHENTICATED
        self._pages = {MAIN_PATH: main}
        self._capabilities = None          # force a re-probe now we are in
        return ActionResult(True, "Signed in to the router.")

    # ------------------------------------------------------- page inventory

    def _menu_paths(self) -> list[str]:
        """Feature-page URLs declared in the JS menu.

        content.asp holds only globals; the actual menu (with the real hyphenated
        page names) is built from MenuNodeConstruction() calls in /JS/menu.js. A
        plain link crawl of content.asp therefore finds nothing, which is why an
        earlier version reported "no MAC-filter page" on a router that plainly
        has one. Reading the menu source is how we learn the true page list.
        """
        body = self._get(MENU_JS, referer=MAIN_PATH)
        if not body:
            return []
        seen: list[str] = []
        for path in _MENU_NODE.findall(body):
            path = path.strip()
            if path and path not in seen:
                seen.append(path)
        return seen

    def _crawl_menu(self, max_pages: int = 40) -> dict[str, str]:
        """Learn the feature pages this firmware ships, without assuming a list.

        Primary source is the JS menu; we fall back to link-crawling the frameset
        for older builds that inline their links. Every fetch carries the Referer
        the feature pages require.
        """
        pages = dict(self._pages)
        main = pages.get(MAIN_PATH) or self._get(MAIN_PATH)
        if main is None:
            return pages
        pages[MAIN_PATH] = main

        queue: list[str] = list(self._menu_paths())
        queue.append(MAIN_PATH)
        visited: set[str] = set()

        while queue and len(pages) < max_pages:
            path = queue.pop(0)
            if path in visited:
                continue
            visited.add(path)
            body = pages.get(path) or self._get(path)
            if body is None:
                continue
            pages[path] = body
            for link in _LINKS.findall(body):
                link = link.strip()
                if not link or link.startswith(("http://", "https://", "javascript:")):
                    continue
                target = link if link.startswith("/") else urljoin(path, link)
                if target not in visited and target not in queue:
                    queue.append(target)

        self._pages = pages
        return pages

    def _find_add_page(self, list_body: str, pages: dict[str, str]) -> Optional[str]:
        """Locate the MAC-filter add sub-page.

        First from a link on the list page (the Add button targets it), then by
        name among the pages already crawled. Returns None if there is no
        distinct add page, in which case the list page carries the form itself.
        """
        for link in _ADD_LINK.findall(list_body):
            link = link.strip()
            if link.startswith(("http://", "https://", "javascript:")):
                continue
            return link if link.startswith("/") else urljoin(self._block_page or "/", link)
        for path in sorted(pages):
            low = path.lower()
            if "add" in low and "filter" in low and "mac" in low:
                return path
        return None

    # ----------------------------------------------------------- capabilities

    def probe_capabilities(self) -> Capabilities:
        probed: list[str] = []
        authed = getattr(self, "_auth_state", AuthState.UNKNOWN) == AuthState.AUTHENTICATED

        if not authed:
            probed.append(f"GET {LOGIN_PATH} (login page reachable)")
            return Capabilities(
                can_block=False,
                method=BlockMethod.NONE,
                can_list_clients=False,
                requires_auth=True,
                auth_state=AuthState.REQUIRED,
                unsupported_reason=(
                    "Sign in to the router to find out whether it offers a blocking "
                    "mechanism. Until then only device discovery is available."
                ),
                alternatives=HUAWEI_ALTERNATIVES,
                probed=probed,
            )

        pages = self._crawl_menu()
        probed.append(f"Crawled {len(pages)} pages from {MAIN_PATH}")

        can_list_early = any(k in p.lower() for p in pages
                             for k in ("lan", "dhcp", "userdev", "sta-device", "hostinfo"))

        # Fast path: the verified HG8547M "X_ATP_Security.MacFilter" contract.
        # If the real MAC-filter page is in the menu, drive it directly with the
        # exact fields confirmed against the device, rather than scraping a form
        # whose Save_Flag/Actionflag a generic guesser would get wrong.
        if MACFILTER_PATH in pages or MACFILTER_PATH in self._menu_paths():
            self._block_page = MACFILTER_PATH
            self._add_page = MACFILTER_ADD_PATH
            self._block_method = BlockMethod.MAC_FILTER
            probed.append(f"MAC filter via ATP contract: {MACFILTER_PATH} + {MACFILTER_ADD_PATH}")
            mode = self._filter_mode()
            probed.append(f"Filter mode: {mode or 'unknown'}")
            return Capabilities(
                can_block=True,
                method=BlockMethod.MAC_FILTER,
                can_list_clients=can_list_early,
                requires_auth=True,
                auth_state=AuthState.AUTHENTICATED,
                unsupported_reason="",
                alternatives=[],
                probed=probed,
            )

        # Prefer the list page as the anchor (the one WITHOUT "add" in its name):
        # it is what we re-read to confirm a block, and it links to the add form.
        # Falling onto an "add" page here would break that read-back, and since
        # "sec_addmacfilter.asp" sorts before "sec_macfilter.asp" a naive first
        # match would do exactly that.
        candidates: list[tuple[str, BlockMethod]] = []
        for path in sorted(pages):
            lowered = path.lower()
            for needles, method in _BLOCK_PAGE_HINTS:
                if any(needle in lowered for needle in needles):
                    candidates.append((path, method))
                    break
        for path, method in candidates:
            if "add" not in path.lower():
                self._block_page, self._block_method = path, method
                break
        if not self._block_page and candidates:
            self._block_page, self._block_method = candidates[0]
        if self._block_page:
            probed.append(f"Found candidate blocking page: {self._block_page}")

        can_list = any("lan" in p.lower() or "dhcp" in p.lower() or "userdev" in p.lower()
                       for p in pages)

        if not self._block_page:
            probed.append("No MAC-filter, ACL, firewall or parental-control page in the menu")
            return Capabilities(
                can_block=False,
                method=BlockMethod.NONE,
                can_list_clients=can_list,
                requires_auth=True,
                auth_state=AuthState.AUTHENTICATED,
                unsupported_reason=(
                    NO_BLOCKING_MESSAGE + " This ONT's web interface exposes no MAC "
                    "filter, access-control list or firewall page to the account you "
                    "signed in with, which is typical of ISP-locked units."
                ),
                alternatives=HUAWEI_ALTERNATIVES,
                probed=probed,
            )

        # The list page (sec_macfilter.asp) has no editable MAC field - the form
        # lives on its "add" sub-page (sec_addmacfilter.asp). Find that page and
        # read the fields from there. Driving the list page is exactly why an
        # earlier attempt looked wired up but never actually blocked anything.
        list_body = pages.get(self._block_page) or self._get(self._block_page) or ""
        self._add_page = self._find_add_page(list_body, pages)
        form_path = self._add_page or self._block_page
        body = pages.get(form_path) or self._get(form_path) or ""
        if form_path != self._block_page:
            self._pages[form_path] = body
            probed.append(f"Add form page: {form_path}")

        fields = set(_INPUT_NAME.findall(body))
        has_mac_field = any("mac" in f.lower() for f in fields)
        probed.append(f"{form_path} form fields: {sorted(fields)[:12]}")

        if not has_mac_field:
            return Capabilities(
                can_block=False,
                method=BlockMethod.NONE,
                can_list_clients=can_list,
                requires_auth=True,
                auth_state=AuthState.AUTHENTICATED,
                unsupported_reason=(
                    NO_BLOCKING_MESSAGE + f" A page at {form_path} was found, "
                    "but it does not expose a MAC address field this app can drive."
                ),
                alternatives=HUAWEI_ALTERNATIVES,
                probed=probed,
            )

        return Capabilities(
            can_block=True,
            method=self._block_method,
            can_list_clients=can_list,
            requires_auth=True,
            auth_state=AuthState.AUTHENTICATED,
            unsupported_reason="",
            alternatives=[],
            probed=probed,
        )

    # -------------------------------------------------------------- blocking

    @staticmethod
    def _parse_inputs(body: str) -> list[dict]:
        """Every <input>/<select> on the page as {name, value, type, checked}.

        Field names are read off the page, not hardcoded, because they differ
        across firmware builds in this family. Radios and checkboxes are marked
        so only the selected one is posted.
        """
        out: list[dict] = []
        for tag in re.findall(r"<(?:input|select)\b[^>]*>", body, re.IGNORECASE):
            name = _INPUT_NAME.search(tag)
            if not name:
                continue
            value = _VALUE_ATTR.search(tag)
            type_m = re.search(r"\btype\s*=\s*[\"']?([a-z]+)", tag, re.IGNORECASE)
            out.append({
                "name": name.group(1),
                "value": value.group(1) if value else "",
                "type": (type_m.group(1).lower() if type_m else "text"),
                "checked": bool(re.search(r"\bchecked\b", tag, re.IGNORECASE)),
            })
        return out

    @staticmethod
    def _mac_for_page(mac: str, body: str) -> str:
        """Format a MAC the way this page's own examples are written."""
        canon = mac.strip().lower().replace("-", ":")
        if re.search(r"[0-9a-f]{2}-[0-9a-f]{2}", body, re.IGNORECASE):
            return canon.replace(":", "-")
        return canon

    # --------------------------------------------- verified HG8547M ATP contract

    def _on_atp_contract(self) -> bool:
        return self._block_page == MACFILTER_PATH

    def _filter_mode(self) -> Optional[str]:
        """"Black" or "White" - the current MAC-filter direction, or None."""
        body = self._get(MACFILTER_PATH, referer=MAIN_PATH) or ""
        m = re.search(r"""var\s+Mode\s*=\s*["'](Black|White)""", body, re.IGNORECASE)
        if m:
            return m.group(1).capitalize()
        # Fall back to which FilterMode radio is checked (0=Black, 1=White).
        for field in self._parse_inputs(body):
            if field["name"].lower() == "filtermode" and field["checked"]:
                return "White" if field["value"] == "1" else "Black"
        return None

    def _list_entries(self) -> list[dict]:
        """Current filter rows: {name, mac, enable} in menu order.

        The list frame renders its rows in JavaScript as
        stMacFilter(domain, Name, MACAddress, Enable) calls, so the row's array
        index - which the delete form needs - is just its position here.

        The CGI only emits its rows if its parent page was fetched first in the
        same session; read on its own it returns an empty table. Priming the
        parent here is essential - skipping it made unblock see an empty list,
        conclude "nothing to remove", and report success while the entry stayed.
        """
        self._get(MACFILTER_PATH, referer=MAIN_PATH)   # prime the server state
        body = self._get(MACFILTER_LIST_CGI, referer=MACFILTER_PATH) or ""
        entries: list[dict] = []
        for m in _ST_MACFILTER.finditer(body):
            entries.append({"name": m.group(4), "mac": m.group(6).lower(),
                            "enable": m.group(8)})
        return entries

    def _confirm_presence(self, mac: str, want_present: bool,
                          tries: int = 4, delay: float = 0.8) -> bool:
        """Poll the list until it reflects the write, or give up.

        The box commits a Save_Flag change a beat after it answers the POST, and
        its list frame reads back eventually-consistent, so a single immediate
        read can miss a change that did take. Polling turns that into a reliable
        yes/no instead of a false failure.
        """
        import time

        mac_canon = mac.strip().lower().replace("-", ":")
        present = mac_canon in [e["mac"] for e in self._list_entries()]
        for _ in range(tries - 1):
            if present == want_present:
                return present
            time.sleep(delay)
            present = mac_canon in [e["mac"] for e in self._list_entries()]
        return present

    def _atp_add(self, mac: str) -> ActionResult:
        """Add a deny rule via the confirmed sec-addmacfilter.asp POST."""
        mac_fmt = mac.strip().upper().replace("-", ":")
        tail = mac_fmt.replace(":", "")[-6:].lower()
        payload = {
            "Save_Flag": "1",              # btnSubmit sets this to 1 to persist
            "EnableMac_Flag": "Yes",
            "curNum": "0",
            "RuleType_Flag": "MAC",
            "Direction_Flag": "Incoming",
            "IpMacType_Flag": "Mac",
            "Actionflag": "Add",
            "Interface_Flag": "br0",
            "Selected_Menu": "Security->MAC Filter",
            "Name": f"blk{tail}",          # alphanumeric, passes isValidName
            "SourceMACAddress": mac_fmt,
            "Enable": "on",                # unvalued checkbox -> "on" when ticked
        }
        resp = self._post_form(MACFILTER_ADD_PATH, payload, referer=MACFILTER_ADD_PATH)
        if resp is None:
            return ActionResult(False, "The router did not accept the add request.")
        if resp.status_code != 200:
            return ActionResult(False, f"The router returned HTTP {resp.status_code}.")

        present = self._confirm_presence(mac_fmt, want_present=True)
        if not present:
            mode = self._filter_mode()
            extra = (" The filter is in Whitelist mode - switch it to Blacklist on the "
                     "router for Block to deny." if mode == "White" else "")
            return ActionResult(
                False,
                "The router accepted the request but the device is not in its filter "
                "list afterwards, so the block did not take effect." + extra,
                method=BlockMethod.MAC_FILTER,
            )
        msg = f"{mac_fmt} blocked on the router."
        if self._filter_mode() == "White":
            msg += (" Note: the filter is in Whitelist mode, so this entry ALLOWS the "
                    "device. Switch to Blacklist on the router to deny it.")
        return ActionResult(True, msg, method=BlockMethod.MAC_FILTER, detail="via sec-addmacfilter.asp")

    def _atp_remove(self, mac: str) -> ActionResult:
        """Delete a rule via the confirmed sec-macfilter.asp Actionflag=Del POST."""
        mac_canon = mac.strip().lower().replace("-", ":")
        entries = self._list_entries()
        index = next((i for i, e in enumerate(entries) if e["mac"] == mac_canon), None)
        if index is None:
            return ActionResult(True, f"{mac} is not in the router's filter list.",
                                method=BlockMethod.MAC_FILTER)
        mode = self._filter_mode() or "Black"
        payload = {
            "ListType_Flag": mode,
            "Mac_Flag": "3",              # removeClick() sets this to 3 for a delete
            "delnum": f"{index},",        # comma-terminated list of row indices
            "EnMacFilter_Flag": "1",
            "mac_num": str(len(entries)),
            "Actionflag": "Del",
            "IpMacType_Flag": "Mac",
            "isFilter": "on",
            "FilterMode": "1" if mode == "White" else "0",
            "Selected_Menu": "Security->MAC Filter",
        }
        resp = self._post_form(MACFILTER_PATH, payload, referer=MACFILTER_PATH)
        if resp is None:
            return ActionResult(False, "The router did not accept the delete request.")
        if resp.status_code != 200:
            return ActionResult(False, f"The router returned HTTP {resp.status_code}.")

        still = self._confirm_presence(mac_canon, want_present=False)
        if still:
            return ActionResult(
                False,
                "The router accepted the request but the device is still in its filter "
                "list, so the unblock did not take effect.",
                method=BlockMethod.MAC_FILTER,
            )
        return ActionResult(True, f"{mac} unblocked on the router.",
                            method=BlockMethod.MAC_FILTER, detail="via sec-macfilter.asp")

    # --------------------------------------------- generic fallback (other builds)

    def _add_filter(self, mac: str) -> ActionResult:
        """Add the MAC to the deny list via the add sub-page's form."""
        form_path = self._add_page or self._block_page
        if not form_path:
            return ActionResult(False, NO_BLOCKING_MESSAGE)
        body = self._pages.get(form_path) or self._get(form_path)
        if body is None:
            return ActionResult(False, "The router's MAC-filter add page is no longer reachable.")

        action_match = _FORM_ACTION.search(body)
        target = self._resolve_target(form_path, action_match.group(1) if action_match else "")

        mac_fmt = self._mac_for_page(mac, body)
        octets = mac_fmt.replace("-", ":").split(":")
        mac_inputs = [i for i in self._parse_inputs(body) if "mac" in i["name"].lower()]
        split_mac = len(mac_inputs) >= 6      # some builds split the MAC into 6 octet boxes
        code = self._check_code()
        name_used = False
        mac_octet_i = 0

        payload: dict[str, str] = {}
        for field in self._parse_inputs(body):
            name, low, ftype = field["name"], field["name"].lower(), field["type"]
            if "mac" in low:
                if split_mac:
                    payload[name] = octets[mac_octet_i] if mac_octet_i < len(octets) else ""
                    mac_octet_i += 1
                else:
                    payload[name] = mac_fmt
            elif "enable" in low or "active" in low:
                payload[name] = "1"
            elif any(hint in low for hint in _CHECKCODE_FIELD_HINTS):
                # Both the visible box and any hidden confirm field get the same
                # code; the router only ever compares them to each other.
                payload[name] = code
            elif ftype in ("radio", "checkbox"):
                if field["checked"]:
                    payload[name] = field["value"] or "1"
            elif not name_used and ftype in ("text",) and "mac" not in low and field["value"] == "":
                # The remaining empty text box is the rule name.
                payload[name] = f"blk-{octets[-1]}"
                name_used = True
            else:
                payload.setdefault(name, field["value"])

        # Echo the anti-CSRF token if the page carries one.
        token = self._named_input_value(body, _TOKEN_TAG)
        token_tag = _TOKEN_TAG.search(body)
        if token_tag and token is not None:
            token_name = _INPUT_NAME.search(token_tag.group(0))
            if token_name:
                payload[token_name.group(1)] = token

        return self._submit_and_confirm(target, payload, form_path, mac, expect_present=True)

    def _remove_filter(self, mac: str) -> ActionResult:
        """Delete the MAC's row from the list page's delete form."""
        if not self._block_page:
            return ActionResult(False, NO_BLOCKING_MESSAGE)
        body = self._get(self._block_page)
        if body is None:
            return ActionResult(False, "The router's MAC-filter page is no longer reachable.")

        mac_canon = mac.strip().lower().replace("-", ":")
        # Find the row for this MAC and the checkbox/hidden id that selects it.
        rows = re.split(r"(?i)</tr>", body)
        target_id = None
        for row in rows:
            macs = [m.lower() for m in _MAC_IN_TEXT.findall(row.replace("-", ":"))]
            if mac_canon in macs:
                sel = re.search(r"""name\s*=\s*["']([^"']*(?:del|select|index|id|chk)[^"']*)["']""",
                                row, re.IGNORECASE)
                if sel:
                    target_id = sel.group(1)
                break
        if target_id is None:
            # Already absent, or the page does not expose a per-row delete we can drive.
            present = mac_canon in [m.lower() for m in _MAC_IN_TEXT.findall(body.replace("-", ":"))]
            if not present:
                return ActionResult(True, f"{mac} is not in the router's filter list.",
                                    method=self._block_method)
            return ActionResult(
                False,
                "This build's MAC-filter page has no per-row delete this app can drive. "
                "Remove the entry from the router's MAC Filter page in a browser.",
                method=self._block_method,
            )

        action_match = _FORM_ACTION.search(body)
        target = self._resolve_target(self._block_page, action_match.group(1) if action_match else "")
        payload: dict[str, str] = {}
        for field in self._parse_inputs(body):
            name, ftype = field["name"], field["type"]
            if ftype in ("radio", "checkbox"):
                if field["checked"] or name == target_id:
                    payload[name] = field["value"] or "1"
            else:
                payload.setdefault(name, field["value"])
        payload[target_id] = payload.get(target_id) or "1"
        for hint in ("Delete", "delete", "DeleteAll", "cmd"):
            if hint in payload:
                payload[hint] = "1"

        return self._submit_and_confirm(target, payload, self._block_page, mac, expect_present=False)

    def _submit_and_confirm(self, target: str, payload: dict, referer_path: str,
                            mac: str, expect_present: bool) -> ActionResult:
        """POST the form, then re-read the list page and verify it actually took."""
        try:
            response = self._http().post(
                target, data=payload,
                headers={"Content-Type": "application/x-www-form-urlencoded",
                         "Referer": urljoin(self.base, referer_path)},
            )
        except httpx.HTTPError as exc:
            return ActionResult(False, f"The router did not accept the request: {exc.__class__.__name__}")
        if response.status_code != 200:
            return ActionResult(False, f"The router returned HTTP {response.status_code}.")

        # Authoritative check: re-read the list page and look for the MAC.
        self._pages.pop(self._block_page, None)
        refreshed = self._get(self._block_page or "") or ""
        macs = [m.lower() for m in _MAC_IN_TEXT.findall(refreshed.replace("-", ":"))]
        present = mac.strip().lower().replace("-", ":") in macs

        if expect_present and not present:
            return ActionResult(
                False,
                "The router accepted the request but the device is not in its filter "
                "list afterwards, so the block did not take effect. If the list is in "
                "Whitelist mode, switch it to Blacklist on the router first.",
                method=self._block_method,
            )
        if not expect_present and present:
            return ActionResult(
                False,
                "The router accepted the request but the device is still in its "
                "filter list, so the unblock did not take effect.",
                method=self._block_method,
            )

        verb = "blocked on the router" if expect_present else "unblocked on the router"
        return ActionResult(True, f"{mac} {verb}.", method=self._block_method,
                            detail=f"via {self._add_page or self._block_page}")

    def _block(self, mac: str, ip: Optional[str]) -> ActionResult:
        if self._on_atp_contract():
            return self._atp_add(mac)
        warn = self._whitelist_warning()
        result = self._add_filter(mac)
        if warn and result.ok:
            result.message += " " + warn
        return result

    def _unblock(self, mac: str, ip: Optional[str]) -> ActionResult:
        if self._on_atp_contract():
            return self._atp_remove(mac)
        return self._remove_filter(mac)

    def _whitelist_warning(self) -> str:
        """Warn if the filter is in Whitelist mode, where 'add' does the opposite."""
        if not self._block_page:
            return ""
        body = self._pages.get(self._block_page) or self._get(self._block_page) or ""
        if _WHITELIST_CHECKED.search(body):
            return ("Note: the router's MAC filter is in Whitelist mode, so this entry "
                    "allows the device rather than denying it. Switch the mode to "
                    "Blacklist on the router for Block to actually deny.")
        return ""

    def blocked_macs(self) -> list[str]:
        if self._on_atp_contract():
            return sorted({e["mac"] for e in self._list_entries()})
        if not self._block_page:
            return []
        body = self._get(self._block_page) or ""
        return sorted({m.lower() for m in _MAC_IN_TEXT.findall(body.replace("-", ":"))})

    # --------------------------------------------------------------- clients

    def list_clients(self) -> dict[str, dict]:
        """Attached clients from whichever LAN/DHCP page this build ships."""
        if getattr(self, "_auth_state", None) != AuthState.AUTHENTICATED:
            return {}
        clients: dict[str, dict] = {}
        for path, body in self._crawl_menu().items():
            low = path.lower()
            if not any(k in low for k in ("lan", "dhcp", "userdev", "hostinfo")):
                continue
            for mac in _MAC_IN_TEXT.findall(body.replace("-", ":")):
                clients.setdefault(mac.lower(), {"source": path})
        return clients

    def logout(self) -> None:
        # This box allows a single admin session, so freeing it on the way out
        # matters: a leaked session blocks the next login until it times out.
        # Hit the real logout.cgi (what the UI's Log Out uses) and the legacy
        # Logoff param, and swallow anything either raises.
        if self._client is not None:
            for call in (
                lambda: self._client.get("/cgi-bin/logout.cgi",
                                         headers={"Referer": urljoin(self.base, MAIN_PATH)}),
                lambda: self._client.get(LOGIN_PATH, params={"Logoff": "1"}),
            ):
                try:
                    call()
                except httpx.HTTPError:
                    pass
            self._client.close()
            self._client = None
        self._pages = {}
        self._block_page = None
        self._add_page = None
        self._auth_state = AuthState.UNKNOWN
        super().logout()
