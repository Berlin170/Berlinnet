# LAN Device Manager

Discovers the devices on your local network, identifies them as far as they can
honestly be identified, and drives router-level blocking **when the router
actually supports it**.

Runs entirely on your own machine. The UI is a local web page served from
`127.0.0.1`; nothing is sent anywhere except to your own router.

## Running it

```
run.bat
```

That installs the three dependencies on first run and opens
<http://127.0.0.1:8765/>.

Manually, if you prefer:

```
python -m pip install -r requirements.txt
python -m lan_device_manager
```

Other commands:

| Command | What it does |
| --- | --- |
| `python -m lan_device_manager` | Start the app and open the dashboard |
| `python -m lan_device_manager --scan` | One scan, printed to the terminal, then exit |
| `python -m lan_device_manager --fetch-oui` | Download the full IEEE vendor registry |
| `python -m lan_device_manager --no-browser` | Start without opening a browser |
| `python -m tests.test_core` | Run the offline regression tests (26 of them) |

Administrator rights are **not** required. Everything uses ordinary sockets and
the standard Windows networking tools.

## What it found on this network

The app was built and tested against the network it now runs on:

```
Interface : Ethernet (Realtek Gaming 2.5GbE Family Controller)
Address   : 192.168.1.10/24
Subnet    : 192.168.1.0/24
Gateway   : 192.168.1.1
Router    : Huawei HG8547M, Boa/0.94.13, ports 23/53/80/5555/7547
```

None of that is hardcoded. The gateway comes from the routing table, the subnet
from the adapter's netmask, and the model from a string the router's own login
page publishes.

## Architecture

```
  net/interfaces.py   detect interface, address, subnet, gateway
          |
  net/probe.py + arp.py + hostname.py     ICMP, TCP, ARP, DNS/NetBIOS/mDNS
          |
  net/scanner.py      orchestration          <- Network Scanner
          |
  net/oui.py + classify.py                   <- Device Identification
          |
  db.py               SQLite                 <- Device Database
          |
  routers/registry.py + adapters             <- Router Integration
          |
  routers/*.block()                          <- Blocking / Unblocking
```

The four stages are genuinely separate: the scanner never talks to the router,
the router layer never writes device records, and blocking only ever happens
through an adapter that has confirmed it can actually block.

## Discovery

Each scan runs, in order:

1. **ARP / neighbour cache** read (`Get-NetNeighbor`, falling back to `arp -a`).
2. **ICMP sweep** of every host in the subnet, in a thread pool.
3. **TCP connect probe** of hosts that ignored ICMP - phones on battery saver
   and firewalled Windows machines are invisible to ping alone.
4. **Second ARP read**, which now has MACs for everything the sweep touched.
5. **Service probe** of the hosts that are alive, which is what makes device
   categorisation work.
6. **Hostname resolution** by mDNS, reverse DNS and NetBIOS.
7. **nmap** enrichment if nmap happens to be installed (`-sn`, discovery only).
8. **DHCP lease names** from the router, if the adapter managed to sign in.

Per device you get IP, MAC, hostname, vendor, category, first seen, last seen,
online state, open ports, and which methods it responded to.

### Wired or Wi-Fi

Each live host is pinged several times and classified by round-trip time and
jitter:

* **Wired** — under 1.5ms, steady. Switched Ethernet is always this fast.
* **Wi-Fi** — 15ms or more, or a spread of 25ms or more. A wireless client with
  power saving parks its radio between beacons, so replies arrive late and
  erratically. Weak signal widens the spread further.
* **Unknown** — anything in between, or a host that stayed silent. Close-range
  Wi-Fi can beat 3ms, so the app refuses to call that wired.

This is the most useful split when every client uses a randomised MAC: it
separates your own equipment from someone else's phone without needing any
cooperation from the device. Filter by **On Wi-Fi** to see exactly who is using
the router's wireless.

### About vendors on this network

Every client here uses a **randomised (locally administered) MAC**. That is a
privacy feature in modern Android and iOS: the device invents a MAC per network
and rotates it. There is no manufacturer to look up, so the app says
`Randomised MAC (private address)` rather than inventing a vendor.

A practical consequence: when a phone rotates its address it will legitimately
appear as a brand new device. That is the privacy feature working, not a bug.

Run `--fetch-oui` to get the full IEEE registry (40,000+ prefixes) for the
devices that do use a real burned-in address.

## Blocking - read this

The app will not pretend. Blocking is only offered when a router mechanism has
been **confirmed to exist**, and the Block button stays disabled otherwise with
the reason shown on the Router card.

**On this network specifically:** the question is still open, and the app says so
rather than guessing either way.

What is known without logging in: the HG8547M serves only two pages to an
anonymous client — the login form at `/cgi-bin/index2.asp` and the post-login
frameset at `/cgi-bin/content.asp`. Probing ~50 plausible feature-page names
(`macfilter.asp`, `acl.asp`, `firewall.asp`, and so on) returns 404 for every
one — but so do `wlan.asp`, `lan.asp` and `status.asp`, and this router
self-evidently *has* Wi-Fi and LAN settings. So the 404s show only that this
firmware build uses page names other than the obvious ones. They are not
evidence that filtering is absent.

The real page names live in the JS menu at `/JS/menu.js` (as `MenuNodeConstruction`
entries), not in `content.asp`, which only holds globals - so `HuaweiAdapter`
reads the menu source after login to learn the true page list instead of shipping
a hardcoded one. Sign in with Connect and the app gives a definitive answer; if a
filtering page exists for your account it enables blocking automatically.

The following is **verified against a live HG8547M** (Boa 0.94), not assumed:

* **Login.** The session id is generated by the browser, not the server:
  `boasid` + 8 hex, cookied before the POST. The "check code" is likewise
  client-side - the login page builds it with `getRandomLetterNum` /
  `Math.random().toString(36)` and only compares it in the browser - so the
  adapter submits a code of the same shape. The `PSW` cookie *is* the session
  and is kept for its whole life (dropping it early logs you straight back out).
* **Referer.** Every feature page 401s unless the request carries a Referer back
  to `content.asp`; the adapter sends it on all authenticated requests.
* **Two pages, hyphenated.** `sec-macfilter.asp` lists the rules, sets the mode
  and deletes; `sec-addmacfilter.asp` is the add form. (The list sub-frame is
  `sec_macfilter`**`list`**`.cgi`, with an underscore - the names really are
  mixed.) Rows are rendered in JS as `stMacFilter(domain, Name, MAC, Enable)`.
* **Block** posts to `sec-addmacfilter.asp` with `Actionflag=Add`,
  `Save_Flag=1`, `Enable=on` and the rule fields. **Unblock** posts to
  `sec-macfilter.asp` with `Actionflag=Del` and the row index in `delnum`.
* Adding a MAC only *denies* it in **Blacklist** mode; in Whitelist mode the
  adapter says so rather than quietly allowing the device.
* Every change is confirmed by re-reading the list, and because the box commits
  a beat late and reads back eventually-consistent, the check polls a few times -
  so a real change is never reported as a false failure, and a failed one is
  never reported as success.

Note this ONT allows a **single admin session** at a time. Log out of the
router's own web page in your browser before using Connect, or the router will
refuse the second session until the first times out. The app frees its session
(via `logout.cgi`) as soon as it is done.

What the app **does not** do, and will not be made to do:

* no Wi-Fi deauthentication attacks
* no ARP spoofing dressed up as "blocking"
* no password guessing or brute force
* no exploiting the known bugs in this firmware family

Those are attacks, not features, and the first two do not even work reliably.

### What actually works instead

* A MAC filter or ACL page in the router's own UI, if your account can see one.
* Asking the ISP to enable filtering, or for the superadmin account.
* Putting your own router behind the ONT - an OpenWrt one is directly supported
  by this app and gives real, enforced firewall blocking.
* A managed access point with client blocking.
* Changing the Wi-Fi password and reconnecting only devices you recognise. On an
  ONT you do not fully control, this is the reliable option.
* If a device routes *through* this PC, the local-gateway adapter can block it
  with a real Windows Firewall rule.

## Interface

The dashboard is a single local page with no build step.

* **Light and dark**, following the system by default. The header button cycles
  system → light → dark and the choice is remembered.
* **Table or card view**, toggled in the toolbar and remembered. `?view=cards`
  makes a layout linkable.
* **Type icons** per device (router, phone, computer, printer, camera, NAS, IoT,
  console, VM) so the list is scannable without reading every row.
* **Colour rails** mark the rows that matter — accent for new devices, red for
  blocked ones.
* **Stat tiles double as filters.** Click one to filter, click it again to clear.
* **Sortable columns** (device, IP, status) and live search across name, IP, MAC,
  vendor, category and notes.
* **Keyboard**: `/` focuses search, `s` starts a scan, `t` changes theme,
  `Esc` closes the drawer or dialog.
* **Responsive**: below 720px the table becomes stacked, labelled blocks rather
  than something you have to scroll sideways.
* Reduced-motion preferences are respected, and focus rings are visible
  throughout.

## Device identity

Devices are keyed on MAC where one is known and on IP otherwise, so a device
that changes address keeps its name, notes and history. A host that answers
ICMP before its MAC reaches the ARP cache is stored under an IP key and then
**promoted** to a MAC key once the MAC is learned - it does not turn into a
second row and strand your custom name on the old one.

"Blocked" is not a label you can apply by hand. It is only ever recorded when a
router actually confirmed the block, which is why the detail panel offers only
Trusted and Unknown.

## Tests

```
python -m tests.test_core
```

Covers storage identity and merging, the IP-to-MAC promotion, offline
transitions, vendor lookup including randomised MACs, classification, the mDNS
answer walker, credential round-tripping and redaction, and the rules that stop
an adapter claiming a blocking capability it has not confirmed.

## Router adapters

| Adapter | Status |
| --- | --- |
| `huawei` | Full login + page discovery + filter driving for Boa-based HG8xxx ONTs |
| `openwrt` | Full ubus JSON-RPC integration; real firewall rules |
| `tplink` | Detection and identification; blocking not implemented |
| `zte` | Detection and identification; blocking not implemented |
| `generic` | Fallback - identifies what it can, reports no blocking |
| `local_gateway` | Windows Firewall rules, only when this PC actually routes the traffic |

Adding a router means adding one subclass of `RouterAdapter` in
`lan_device_manager/routers/` and listing it in `registry.py`. Nothing in the
scanner or the UI changes.

`tplink` and `zte` deliberately stop at detection. TP-Link alone ships at least
four incompatible web stacks, and shipping a Block button built on a guess about
which one you have is exactly the dishonesty this app is meant to avoid.

## Credentials

Router passwords are encrypted with the Windows Data Protection API before they
touch the disk, keyed to your Windows account. They are never logged, never
returned by the API, and only stored at all if you tick the box.

Note that the HG8547M's web interface is plain HTTP with no TLS listener, so the
password crosses your LAN in the clear. That is the firmware's design and no
client can fix it. The app refuses to send credentials to anything that is not a
private address.

## Storage

Everything lives in `%LOCALAPPDATA%\LanDeviceManager`:

* `devices.db` - SQLite: devices, history, settings
* `oui.csv` - the IEEE registry, if you downloaded it

Delete `devices.db` to start over.

## Security notes

* The API binds to loopback only and has no authentication, because nothing
  remote can reach it. If you ever pass `--host 0.0.0.0`, add authentication
  first - the API can drive router credentials.
* Scans are limited to the subnet of the interface you selected, and the app
  refuses to sweep anything larger than a /20.
* The app never writes to the ARP table, only reads it.
* The only outbound internet request it can make is `--fetch-oui`, and only when
  you run that command.

## Requirements

Windows 10/11, Python 3.10+, and `fastapi`, `uvicorn`, `httpx`.

The frontend is plain HTML/CSS/JS with no build step, so the whole app starts
with one command and works offline. A React or Next.js build would have added a
Node toolchain and a bundle step for a dashboard that is one page of tables -
the tradeoff was not worth it here. The backend follows the requested stack:
Python for discovery, FastAPI for the local API, SQLite for storage.
