"""FastAPI web application for Graboid."""

import asyncio
import base64
import hashlib
import hmac
import json
import logging
import os
import secrets
import time
from pathlib import Path
from typing import Any

import tomllib
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Request, Form, Depends, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from ..browser import get_notes_db
from ..orchestrator import Config, CONFIG_SEARCH_PATHS, EXAMPLE_CONFIG

logger = logging.getLogger(__name__)

# Auth settings
DEFAULT_USERNAME = os.environ.get("GRABOID_USERNAME", "admin")
DEFAULT_PASSWORD = os.environ.get("GRABOID_PASSWORD", "adminadmin")
SESSION_SECRET = os.environ.get("GRABOID_SESSION_SECRET", secrets.token_hex(32))
SESSION_MAX_AGE = 60 * 60 * 24 * 7  # 7 days

# FastAPI app
app = FastAPI(title="Graboid", version="0.1.0")

# Templates
TEMPLATE_DIR = Path(__file__).parent / "templates"
templates = Jinja2Templates(directory=str(TEMPLATE_DIR))


def sign_session(username: str) -> str:
    """Create a signed session token."""
    timestamp = str(int(time.time()))
    data = f"{username}:{timestamp}"
    signature = hmac.new(SESSION_SECRET.encode(), data.encode(), hashlib.sha256).hexdigest()
    return base64.urlsafe_b64encode(f"{data}:{signature}".encode()).decode()


def verify_session(token: str) -> str | None:
    """Verify session token and return username if valid."""
    try:
        decoded = base64.urlsafe_b64decode(token.encode()).decode()
        username, timestamp, signature = decoded.rsplit(":", 2)

        # Check signature
        expected = hmac.new(SESSION_SECRET.encode(), f"{username}:{timestamp}".encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(signature, expected):
            return None

        # Check expiration
        if int(time.time()) - int(timestamp) > SESSION_MAX_AGE:
            return None

        return username
    except Exception:
        return None


def get_current_user(request: Request) -> str | None:
    """Get current user from session cookie."""
    token = request.cookies.get("graboid_session")
    if not token:
        return None
    return verify_session(token)


def require_auth(request: Request) -> str:
    """Dependency that requires authentication."""
    user = get_current_user(request)
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")
    return user


# Global state for browser monitoring
class AppState:
    def __init__(self):
        self.browser_screenshot: bytes | None = None
        self.browser_url: str = ""
        self.agent_messages: list[dict[str, Any]] = []
        self.downloads: list[dict[str, Any]] = []
        self.is_running: bool = False
        self.current_task: str = ""
        self.websockets: list[WebSocket] = []
        self.config: Config | None = None
        self.config_path: Path | None = None

    async def broadcast(self, message: dict):
        """Send message to all connected WebSocket clients."""
        for ws in self.websockets[:]:
            try:
                await ws.send_json(message)
            except Exception:
                self.websockets.remove(ws)

    def add_message(self, role: str, content: str):
        """Add an agent message."""
        msg = {"role": role, "content": content}
        self.agent_messages.append(msg)
        # Keep last 100 messages
        if len(self.agent_messages) > 100:
            self.agent_messages = self.agent_messages[-100:]

    async def update_screenshot(self, screenshot: bytes, url: str):
        """Update browser screenshot and notify clients."""
        self.browser_screenshot = screenshot
        self.browser_url = url
        await self.broadcast({
            "type": "screenshot",
            "data": base64.b64encode(screenshot).decode(),
            "url": url,
        })

    async def update_status(self, is_running: bool, task: str = ""):
        """Update agent status."""
        self.is_running = is_running
        self.current_task = task
        await self.broadcast({
            "type": "status",
            "is_running": is_running,
            "task": task,
        })


state = AppState()


def find_config_file() -> Path | None:
    """Find existing config file."""
    for path in CONFIG_SEARCH_PATHS:
        if path.exists():
            return path
    return None


def load_config_as_dict() -> dict[str, Any]:
    """Load config file as dictionary."""
    path = find_config_file()
    if path and path.exists():
        with open(path, "rb") as f:
            return tomllib.load(f)
    return {}


def save_config(data: dict[str, Any], path: Path | None = None):
    """Save config to TOML file."""
    if path is None:
        path = find_config_file() or CONFIG_SEARCH_PATHS[0]

    lines = []
    for key, value in data.items():
        if isinstance(value, bool):
            lines.append(f"{key} = {str(value).lower()}")
        elif isinstance(value, str):
            lines.append(f'{key} = "{value}"')
        elif isinstance(value, list):
            items = ", ".join(f'"{v}"' for v in value)
            lines.append(f"{key} = [{items}]")
        else:
            lines.append(f"{key} = {value}")

    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w") as f:
        f.write("\n".join(lines) + "\n")


@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    """Login page."""
    user = get_current_user(request)
    if user:
        return RedirectResponse(url="/", status_code=303)
    error = request.query_params.get("error")
    return templates.TemplateResponse("login.html", {
        "request": request,
        "error": error,
    })


@app.post("/login")
async def login(request: Request, username: str = Form(...), password: str = Form(...)):
    """Handle login form submission."""
    if username == DEFAULT_USERNAME and password == DEFAULT_PASSWORD:
        response = RedirectResponse(url="/", status_code=303)
        token = sign_session(username)
        response.set_cookie(
            key="graboid_session",
            value=token,
            max_age=SESSION_MAX_AGE,
            httponly=True,
            samesite="lax",
        )
        return response
    return RedirectResponse(url="/login?error=1", status_code=303)


@app.get("/logout")
async def logout():
    """Log out the current user."""
    response = RedirectResponse(url="/login", status_code=303)
    response.delete_cookie("graboid_session")
    return response


@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    """Main dashboard page."""
    user = get_current_user(request)
    if not user:
        return RedirectResponse(url="/login", status_code=303)
    return templates.TemplateResponse("index.html", {
        "request": request,
        "user": user,
        "is_running": state.is_running,
        "current_task": state.current_task,
    })


@app.get("/config", response_class=HTMLResponse)
async def config_page(request: Request):
    """Configuration page."""
    user = get_current_user(request)
    if not user:
        return RedirectResponse(url="/login", status_code=303)

    config_data = load_config_as_dict()
    config_path = find_config_file()

    return templates.TemplateResponse("config.html", {
        "request": request,
        "user": user,
        "config": config_data,
        "config_path": str(config_path) if config_path else "Not found",
    })


@app.post("/config")
async def save_config_form(
    request: Request,
    llm_provider: str = Form("claude_code"),
    llm_model: str = Form("sonnet"),
    torrent_client: str = Form("auto"),
    qbittorrent_host: str = Form("localhost"),
    qbittorrent_port: int = Form(8080),
    qbittorrent_username: str = Form("admin"),
    qbittorrent_password: str = Form("adminadmin"),
    path_mappings: str = Form(""),
    download_dir: str = Form("./downloads"),
    headless: bool = Form(False),
    log_level: str = Form("INFO"),
):
    """Save configuration."""
    user = get_current_user(request)
    if not user:
        return RedirectResponse(url="/login", status_code=303)
    # Parse path mappings (one per line)
    mappings = [m.strip() for m in path_mappings.split("\n") if m.strip()]

    config_data = {
        "llm_provider": llm_provider,
        "llm_model": llm_model,
        "torrent_client": torrent_client,
        "qbittorrent_host": qbittorrent_host,
        "qbittorrent_port": qbittorrent_port,
        "qbittorrent_username": qbittorrent_username,
        "qbittorrent_password": qbittorrent_password,
        "path_mappings": mappings,
        "download_dir": download_dir,
        "headless": headless,
        "log_level": log_level,
    }

    save_config(config_data)
    return RedirectResponse(url="/config?saved=1", status_code=303)


@app.get("/notes", response_class=HTMLResponse)
async def notes_page(request: Request):
    """Agent notes page."""
    user = get_current_user(request)
    if not user:
        return RedirectResponse(url="/login", status_code=303)

    notes_db = get_notes_db()
    stats = notes_db.get_stats()
    domains = notes_db.get_all_domains()

    domain_notes = {}
    for domain in domains:
        domain_notes[domain] = notes_db.get_notes_for_url(f"https://{domain}")

    return templates.TemplateResponse("notes.html", {
        "request": request,
        "user": user,
        "stats": stats,
        "domains": domains,
        "domain_notes": domain_notes,
    })


@app.get("/browser", response_class=HTMLResponse)
async def browser_page(request: Request):
    """Live browser view page."""
    user = get_current_user(request)
    if not user:
        return RedirectResponse(url="/login", status_code=303)

    return templates.TemplateResponse("browser.html", {
        "request": request,
        "user": user,
        "is_running": state.is_running,
        "current_task": state.current_task,
    })


@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    """WebSocket for live updates."""
    await websocket.accept()
    state.websockets.append(websocket)

    try:
        # Send current state
        await websocket.send_json({
            "type": "init",
            "is_running": state.is_running,
            "task": state.current_task,
            "messages": state.agent_messages[-20:],
        })

        # Send current screenshot if available
        if state.browser_screenshot:
            await websocket.send_json({
                "type": "screenshot",
                "data": base64.b64encode(state.browser_screenshot).decode(),
                "url": state.browser_url,
            })

        # Keep connection alive and handle incoming messages
        while True:
            data = await websocket.receive_json()

            if data.get("type") == "ping":
                await websocket.send_json({"type": "pong"})

    except WebSocketDisconnect:
        state.websockets.remove(websocket)
    except Exception as e:
        logger.warning(f"WebSocket error: {e}")
        if websocket in state.websockets:
            state.websockets.remove(websocket)


@app.get("/api/status")
async def get_status():
    """Get current status."""
    return {
        "is_running": state.is_running,
        "task": state.current_task,
        "downloads": state.downloads,
        "message_count": len(state.agent_messages),
    }


@app.get("/api/notes/stats")
async def get_notes_stats():
    """Get notes statistics."""
    notes_db = get_notes_db()
    return notes_db.get_stats()


def get_app_state() -> AppState:
    """Get the global app state for use by other modules."""
    return state


def run_server(host: str = "127.0.0.1", port: int = 8000):
    """Run the web server."""
    import uvicorn
    uvicorn.run(app, host=host, port=port)
