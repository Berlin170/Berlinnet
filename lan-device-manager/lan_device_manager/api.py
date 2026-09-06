"""Local HTTP API.

Binds to 127.0.0.1 only. There is no authentication because there is no remote
access: anything that can reach this API is already running as this user on
this machine. If you ever change HOST away from loopback, add authentication
first - the API can drive router credentials.
"""

from __future__ import annotations

import asyncio
import sys
import threading
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from . import config
from .credentials import is_available as dpapi_available
from .net import oui
from .routers import registry
from .service import AppState

# Frozen builds (PyInstaller) unpack data under sys._MEIPASS; fall back to the
# package directory when running from source.
if getattr(sys, "frozen", False) and hasattr(sys, "_MEIPASS"):
    STATIC_DIR = Path(sys._MEIPASS) / "lan_device_manager" / "static"
else:
    STATIC_DIR = Path(__file__).parent / "static"

state = AppState()
_scan_lock = threading.Lock()


@asynccontextmanager
async def lifespan(_app: FastAPI):
    # Resume periodic scanning if it was on when the app was last closed.
    if state.db.get_setting("monitor_enabled", False):
        state.start_monitor()
    yield
    state.stop_monitor()
    state.db.close()


app = FastAPI(title="LAN Device Manager", version="1.0.0", docs_url="/api/docs",
              lifespan=lifespan)


# ------------------------------------------------------------------ schemas

class DeviceUpdate(BaseModel):
    custom_name: Optional[str] = Field(default=None, max_length=120)
    notes: Optional[str] = Field(default=None, max_length=2000)
    # Deliberately not accepting "blocked" here. Blocked is not an opinion the
    # user can record - it is a fact about the router, and it is only ever set
    # by a block that the router actually confirmed.
    trust: Optional[str] = Field(default=None, pattern="^(trusted|unknown)$")
    acknowledged: Optional[bool] = None


class LoginRequest(BaseModel):
    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1, max_length=128)
    remember: bool = False


class IntervalRequest(BaseModel):
    seconds: int = Field(ge=60, le=86400)


class InterfaceRequest(BaseModel):
    name: str


class AdapterRequest(BaseModel):
    name: str


class SettingRequest(BaseModel):
    name: str
    value: object


# ------------------------------------------------------------------ overview

@app.get("/api/overview")
def overview() -> dict:
    return state.overview()


@app.get("/api/interfaces")
def interfaces() -> dict:
    return {"interfaces": [i.to_dict() for i in state.interfaces()]}


@app.post("/api/interfaces/select")
def select_interface(request: InterfaceRequest) -> dict:
    iface = state.select_interface(request.name)
    if iface is None:
        raise HTTPException(404, "No interface with that name")
    return {"interface": iface.to_dict()}


# --------------------------------------------------------------------- scan

@app.post("/api/scan")
async def scan() -> dict:
    if state.scanner.is_running:
        raise HTTPException(409, "A scan is already running")

    def run_scan() -> dict:
        with _scan_lock:
            return state.scan_now()

    try:
        result = await asyncio.to_thread(run_scan)
    except RuntimeError as exc:
        raise HTTPException(400, str(exc))
    return result


@app.get("/api/scan/status")
def scan_status() -> dict:
    return state.scanner.snapshot()


# ------------------------------------------------------------------ devices

@app.get("/api/devices")
def devices() -> dict:
    return {"devices": state.db.list_devices(), "stats": state.db.stats()}


@app.get("/api/devices/{key:path}/history")
def device_history(key: str) -> dict:
    device = state.db.get_device(key)
    if device is None:
        raise HTTPException(404, "Unknown device")
    return {"device": device, "events": state.db.list_events(limit=200, key=key)}


@app.patch("/api/devices/{key:path}")
def update_device(key: str, request: DeviceUpdate) -> dict:
    if state.db.get_device(key) is None:
        raise HTTPException(404, "Unknown device")
    fields = request.model_dump(exclude_none=True)
    if "acknowledged" in fields:
        fields["acknowledged"] = int(fields["acknowledged"])
    device = state.db.update_device(key, **fields)
    if "trust" in fields:
        state.db.log_event(key, "trust", f"Marked as {fields['trust']}")
    return {"device": device}


@app.delete("/api/devices/{key:path}")
def forget_device(key: str) -> dict:
    if state.db.get_device(key) is None:
        raise HTTPException(404, "Unknown device")
    state.db.delete_device(key)
    return {"ok": True}


@app.post("/api/devices/acknowledge-all")
def acknowledge_all() -> dict:
    return {"updated": state.db.acknowledge_all()}


# ----------------------------------------------------------------- blocking

@app.post("/api/devices/{key:path}/block")
def block(key: str) -> JSONResponse:
    result = state.block_device(key)
    return JSONResponse(result.to_dict(), status_code=200 if result.ok else 409)


@app.post("/api/devices/{key:path}/unblock")
def unblock(key: str) -> JSONResponse:
    result = state.unblock_device(key)
    return JSONResponse(result.to_dict(), status_code=200 if result.ok else 409)


# ------------------------------------------------------------------- router

@app.get("/api/router")
def router() -> dict:
    info = state.router_info()
    adapter = state.adapter()
    if info is None or adapter is None:
        raise HTTPException(404, "No gateway detected on the active interface")
    return {
        "router": info.to_dict(),
        "adapter": {"name": adapter.name, "vendor": adapter.vendor},
        "capabilities": adapter.capabilities().to_dict(),
        "available_adapters": registry.available_adapters(),
        "has_saved_credentials": state.credentials.has_saved(info.ip),
        "can_store_credentials": dpapi_available(),
    }


@app.post("/api/router/refresh")
def router_refresh() -> dict:
    info = state.router_info(refresh=True)
    if info is None:
        raise HTTPException(404, "No gateway detected")
    adapter = state.adapter()
    return {"router": info.to_dict(),
            "capabilities": adapter.capabilities(refresh=True).to_dict() if adapter else None}


@app.post("/api/router/login")
def router_login(request: LoginRequest) -> JSONResponse:
    result = state.router_login(request.username, request.password, request.remember)
    payload = result.to_dict()
    adapter = state.adapter()
    if adapter is not None:
        payload["capabilities"] = adapter.capabilities(refresh=True).to_dict()
    return JSONResponse(payload, status_code=200 if result.ok else 401)


@app.post("/api/router/logout")
def router_logout() -> dict:
    state.router_logout()
    info = state.router_info()
    if info is not None:
        state.credentials.forget(info.ip)
    return {"ok": True}


@app.post("/api/router/adapter")
def set_adapter(request: AdapterRequest) -> dict:
    adapter = state.use_adapter(request.name)
    if adapter is None:
        raise HTTPException(404, "No adapter with that name")
    return {"adapter": {"name": adapter.name, "vendor": adapter.vendor},
            "capabilities": adapter.capabilities(refresh=True).to_dict()}


# ------------------------------------------------------- events + monitoring

@app.get("/api/events")
def events(limit: int = 100) -> dict:
    return {"events": state.db.list_events(limit=min(limit, 500))}


@app.get("/api/notifications")
def notifications() -> dict:
    return {"notifications": state.drain_notifications()}


@app.post("/api/monitor/start")
def monitor_start() -> dict:
    state.start_monitor()
    return {"monitoring": state.monitoring, "interval": state.interval}


@app.post("/api/monitor/stop")
def monitor_stop() -> dict:
    state.stop_monitor()
    return {"monitoring": False}


@app.post("/api/monitor/interval")
def monitor_interval(request: IntervalRequest) -> dict:
    return {"interval": state.set_interval(request.seconds)}


# ----------------------------------------------------------------- settings

@app.get("/api/settings")
def settings() -> dict:
    return {
        "use_nmap": bool(state.db.get_setting("use_nmap", True)),
        "monitor_enabled": bool(state.db.get_setting("monitor_enabled", False)),
        "scan_interval": state.interval,
        "oui_entries": oui.registry_size(),
        "oui_full_registry": oui.has_full_registry(),
        "data_dir": str(config.data_dir()),
    }


@app.post("/api/settings")
def set_setting(request: SettingRequest) -> dict:
    allowed = {"use_nmap"}
    if request.name not in allowed:
        raise HTTPException(400, "That setting cannot be changed here")
    state.db.set_setting(request.name, request.value)
    return {"ok": True}


@app.post("/api/oui/refresh")
def oui_refresh() -> dict:
    """Re-read the IEEE registry file if the user has placed one in the data dir."""
    return {"entries": oui.reload(), "full_registry": oui.has_full_registry(),
            "path": str(config.OUI_PATH)}


# --------------------------------------------------------------------- app

class RevalidatingStatic(StaticFiles):
    """Serve the UI assets with revalidation forced.

    Starlette sends ETag and Last-Modified but no Cache-Control, which leaves
    the browser free to apply heuristic freshness and keep running a stale
    app.js after an edit. no-cache still permits a 304, so this costs a
    conditional request rather than a re-download.
    """

    def file_response(self, *args, **kwargs) -> Response:
        response = super().file_response(*args, **kwargs)
        response.headers["Cache-Control"] = "no-cache"
        return response


@app.get("/")
def index() -> FileResponse:
    return FileResponse(STATIC_DIR / "index.html",
                        headers={"Cache-Control": "no-cache"})


app.mount("/static", RevalidatingStatic(directory=str(STATIC_DIR)), name="static")
