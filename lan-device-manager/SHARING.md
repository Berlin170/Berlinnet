# Sharing this with friends

This is a **local** tool: it scans the network it runs on and talks to that
network's router. It cannot be hosted once for everyone — there is no website to
visit. Each person runs it on their own PC, on their own Wi-Fi.

## For a non-technical friend — send them the .exe

1. Give them **`BerlinNet.exe`** (from `dist/`, or a GitHub Release).
2. They double-click it. A small black window opens and the dashboard appears at
   <http://127.0.0.1:8765>. That's it — no Python, no install.
3. To block devices, they click **Connect** and sign in with **their own**
   router admin login (not yours, not the Wi-Fi password).

Notes to pass on:
- Windows SmartScreen may warn on first run ("Windows protected your PC")
  because the .exe is not code-signed. They click **More info → Run anyway**.
- Some antivirus flags PyInstaller .exes as unknown; that is a false positive for
  a self-built tool. Signing the .exe removes both warnings but costs money.
- Real blocking is automatic only on **Huawei / iLINK HG8xxx** routers (like
  yours). On other routers the panel still shows every device and lets you name
  them; the Block button enables only if it confirms a filter page.

## For a friend who has Python — send them the code

```
git clone <your-repo-url>
cd lan-device-manager
run.bat
```

`run.bat` installs the three dependencies on first run and opens the dashboard.

## Building the .exe yourself (to update it)

```
python -m pip install pyinstaller
python -m PyInstaller --noconfirm --onefile --name BerlinNet --console ^
  --add-data "lan_device_manager/static;lan_device_manager/static" ^
  --collect-submodules lan_device_manager --collect-all uvicorn ^
  --collect-submodules fastapi --collect-submodules httpx --collect-submodules anyio ^
  --hidden-import lan_device_manager.api desktop.py
```

The result is `dist/BerlinNet.exe` — one self-contained file you can hand
to anyone on Windows.

## Putting it on GitHub

1. Create an empty repo on github.com.
2. From this folder: `git init`, `git add .`, `git commit -m "Initial"`, then
   `git remote add origin <url>` and `git push -u origin main`.
3. Upload `BerlinNet.exe` under the repo's **Releases** (don't commit the
   .exe into the source tree — it's large; Releases is the right place).

`.gitignore` already keeps personal data (`devices.json`, the vendor cache) out
of the repo, so nothing about your own network is published.
