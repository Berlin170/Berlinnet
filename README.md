# BerlinNet — Who's on my WiFi

A local panel that shows every device on your network, lets you name them, and
flags anything you haven't recognised yet.

Runs on your own PC. It has to — a scanner needs to be physically on the network
it's scanning, so this cannot be deployed to Vercel or Railway.

## Quick install (Windows) — one command, no setup

Open **Command Prompt** (press the Windows key, type `cmd`, press Enter), then
paste this and press Enter. It downloads BerlinNet and starts it:

```
curl -L -o "%USERPROFILE%\Downloads\BerlinNet.exe" https://github.com/Berlin170/Berlinnet/releases/latest/download/BerlinNet.exe && "%USERPROFILE%\Downloads\BerlinNet.exe"
```

A small window opens and your browser shows the panel at
<http://127.0.0.1:8765>. Click **Connect** and sign in with your **router**
admin login (not the Wi-Fi password) to block or unblock devices.

Next time, just double-click `BerlinNet.exe` in your Downloads folder.

> No Python, no install. If Windows shows a blue "Windows protected your PC"
> box, click **More info → Run anyway** (it appears because the app isn't paid
> code-signing — it's safe, you built it).

> ## Which app should I use?
>
> There are two here. **For real use, use the Python one in
> [`lan-device-manager/`](lan-device-manager/) — it's the recommended app.**
>
> | | `lan-device-manager/` (Python) | this folder (Node) |
> |---|---|---|
> | Discovery | ARP + ICMP + TCP probe + hostname/mDNS/NetBIOS | ping sweep + ARP |
> | Wired vs Wi-Fi split | yes (by round-trip timing) | no |
> | Storage | SQLite | `devices.json` |
> | Router credentials | encrypted (Windows DPAPI) | plain in `router.js` |
> | HG8547M blocking | yes (same driver) | yes (same driver) |
> | Tests | 38, offline | none |
> | Needs Admin | no | yes (for a reliable ping sweep) |
>
> Both drive the exact same HG8547M MAC-filter blocking. The Python app is more
> thorough everywhere else and doesn't need Administrator. Start it with:
>
> ```
> cd lan-device-manager
> run.bat
> ```
>
> The rest of this file documents the lightweight Node app in this folder — a fine
> quick option if you'd rather not install Python.

## Setup

You need Node.js installed. Then, in this folder:

```
npm install
npm start
```

Open http://localhost:3000

The first scan takes about 30 seconds. It pings every address on your subnet,
then reads the ARP table to see who replied.

**On Windows, run your terminal as Administrator.** Without it the ping sweep is
unreliable and you'll see fewer devices than are actually there.

## Using it

- **Name a device** — click its name and type. Now you'll recognise it next time.
- **This is mine** — marks it as known so it stops showing as "Not named".
- Anything online and unnamed shows in amber. That's what to look at.
- The panel rescans every 5 minutes on its own.

Data is stored in `devices.json` next to the app, so names survive a restart.

## About blocking

The Block button marks a device as blocked **in this panel only**. It does not
cut their internet. No software running on your PC can do that — blocking has to
be enforced by the router, and your ONT gives no way in by default.

To actually remove someone from your WiFi: **change the WiFi password.** Your
router is on the factory default (`12345678`), which is almost certainly how
unknown devices got on in the first place. Log in at http://192.168.1.1, find
the WLAN settings, set a real password with WPA2 and AES.

### Making Block real (optional)

On a Huawei / iLINK **HG8xxx** ONT (the HG8547M and its siblings), `router.js`
drives the router's own MAC-filter page the way a browser does, so Block can
actually cut a device off. To turn it on, open `router.js` and set:

```js
enabled: true,
username: 'telecomadmin',   // your ISP account, or superadmin if you have it
password: '...'             // NOT the Wi-Fi password
```

That's it — no path or field names to fill in. This is **verified against a live
HG8547M**. When you press Block the panel:

1. signs in — generating the `boasid…` session id and the login "check code" the
   way the page's own JavaScript does (both are client-side; the server does not
   issue or validate them), and keeping the `PSW` session cookie;
2. reads `/JS/menu.js` to find the real MAC-filter page — `sec-macfilter.asp`
   (hyphen), whose add form is `sec-addmacfilter.asp`; content.asp only holds
   globals, so a naive link-crawl finds nothing;
3. posts the add form (`Actionflag=Add`, `Save_Flag=1`, `Enable=on`) with a
   Referer the router requires, then re-reads the list — polling a few times,
   because the box commits a beat late — to confirm the entry is really there.

Unblock deletes the row by index on `sec-macfilter.asp`. If it can't confirm the
change it says so, rather than claiming success. A block only *denies* the device
when the filter is in **Blacklist** mode; in Whitelist mode the panel warns you
instead. The ONT allows one admin session at a time, so log out of the router's
web page in your browser before using Block. If your ISP account can't see a MAC-filter
page at all (many locked units hide it), the panel says that too — the reliable
fallback is still to change the Wi-Fi password.

> The exchange is plain HTTP with the password in the clear; that's the
> firmware's design, and the panel only ever talks to a router on your own LAN.
> It never guesses passwords, exploits firmware bugs, deauths, or ARP-spoofs.

## Why some devices don't show up

The scan relies on devices answering a ping. Phones on battery saver and some
Windows machines ignore pings, so they can be missed. Run a few scans over a few
minutes to catch everything, and keep names on the devices you do find so the
list gets more useful over time.
