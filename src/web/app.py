"""FastAPI web application for Graboid."""

import asyncio
import base64
import collections
import hashlib
import hmac
import json
import logging
import os
import secrets
import time
from pathlib import Path
from typing import Any

# Remove askpass programs from environment to prevent GUI credential popups
for _askpass_var in ("SSH_ASKPASS", "SUDO_ASKPASS", "GIT_ASKPASS"):
    os.environ.pop(_askpass_var, None)
os.environ["GIT_TERMINAL_PROMPT"] = "0"

# In-memory log buffer for UI
LOG_BUFFER_SIZE = 500
log_buffer: collections.deque = collections.deque(maxlen=LOG_BUFFER_SIZE)


class BufferingLogHandler(logging.Handler):
    """Log handler that keeps recent logs in memory for UI display."""

    def emit(self, record):
        try:
            msg = self.format(record)
            log_buffer.append({
                "time": record.created,
                "level": record.levelname,
                "name": record.name,
                "message": msg,
            })
        except Exception:
            pass


# Install the buffering handler on root logger
_buffer_handler = BufferingLogHandler()
_buffer_handler.setLevel(logging.INFO)
_buffer_handler.setFormatter(logging.Formatter('%(asctime)s %(levelname)s [%(name)s] %(message)s'))
logging.getLogger().addHandler(_buffer_handler)

import tomllib
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Request, Form, Depends, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from platformdirs import user_cache_dir

from ..browser import get_notes_db
from ..orchestrator import Config, CONFIG_SEARCH_PATHS, EXAMPLE_CONFIG
from .api import router as api_router, generate_api_key

logger = logging.getLogger(__name__)

# Auth settings
DEFAULT_USERNAME = os.environ.get("GRABOID_USERNAME", "admin")
DEFAULT_PASSWORD = os.environ.get("GRABOID_PASSWORD", "adminadmin")
SESSION_MAX_AGE = 60 * 60 * 24 * 7  # 7 days

# Stable session secret - use env var or derive from machine-specific data
def _get_session_secret() -> str:
    if secret := os.environ.get("GRABOID_SESSION_SECRET"):
        return secret
    # Derive stable secret from username + password hash (survives restarts)
    import hashlib
    stable_data = f"graboid:{DEFAULT_USERNAME}:{DEFAULT_PASSWORD}:session"
    return hashlib.sha256(stable_data.encode()).hexdigest()

SESSION_SECRET = _get_session_secret()

# Git version info
def _get_git_info() -> dict:
    """Get git hash and file modification time for version display."""
    import subprocess
    from datetime import datetime

    repo_root = Path(__file__).parent.parent.parent
    info = {"hash": "", "timestamp": "", "relative": "", "tz": ""}

    # Set GIT_SSH_COMMAND to prevent any SSH operations
    env = {**os.environ, "GIT_TERMINAL_PROMPT": "0", "GIT_SSH_COMMAND": "false"}

    try:
        # Get short hash (local only, no network)
        result = subprocess.run(
            ["git", "rev-parse", "--short", "HEAD"],
            capture_output=True, text=True, cwd=repo_root, env=env, timeout=5
        )
        if result.returncode == 0:
            info["hash"] = result.stdout.strip()

        # Check for uncommitted changes (local only)
        result = subprocess.run(
            ["git", "status", "--porcelain", "-uno"],  # -uno: don't check untracked
            capture_output=True, text=True, cwd=repo_root, env=env, timeout=5
        )
        has_changes = result.returncode == 0 and result.stdout.strip()

        if has_changes:
            info["hash"] += "*"

        # Get timestamp of most recent commit or file
        # Just use current time for simplicity if there are changes
        if has_changes:
            dt = datetime.now()
        else:
            result = subprocess.run(
                ["git", "log", "-1", "--format=%ct"],
                capture_output=True, text=True, cwd=repo_root, env=env, timeout=5
            )
            if result.returncode == 0:
                ts = int(result.stdout.strip())
                dt = datetime.fromtimestamp(ts)
            else:
                dt = datetime.now()

        info["timestamp"] = dt.strftime("%Y-%m-%d %H:%M:%S")
        info["tz"] = dt.astimezone().strftime("%Z")

        # Calculate relative time
        now = datetime.now()
        diff = now - dt
        if diff.days > 0:
            info["relative"] = f"{diff.days}d ago"
        elif diff.seconds >= 3600:
            info["relative"] = f"{diff.seconds // 3600}h ago"
        elif diff.seconds >= 60:
            info["relative"] = f"{diff.seconds // 60}m ago"
        else:
            info["relative"] = "just now"
    except Exception:
        pass
    return info

GIT_INFO = _get_git_info()

# FastAPI app
app = FastAPI(title="Graboid", version="0.1.0")

# Include API router
app.include_router(api_router)

# Templates
TEMPLATE_DIR = Path(__file__).parent / "templates"
templates = Jinja2Templates(directory=str(TEMPLATE_DIR))

# Add git info to all template contexts
templates.env.globals["git"] = GIT_INFO


@app.on_event("startup")
async def startup_event():
    """Initialize job queue, runner, and credential store on startup."""
    from platformdirs import user_data_dir

    # Credential store disabled - was causing GUI password prompts
    # To re-enable, uncomment and set GRABOID_USE_KEYRING=1
    # try:
    #     from ..credentials import CredentialStore
    #     state.credential_store = CredentialStore()
    # except Exception as e:
    #     logger.warning(f"Failed to initialize credential store: {e}")
    state.credential_store = None

    # Initialize job queue
    try:
        from ..jobs import JobDatabase, JobQueue

        data_dir = Path(user_data_dir("graboid", "graboid"))
        db_path = data_dir / "jobs.db"
        db_path.parent.mkdir(parents=True, exist_ok=True)

        db = JobDatabase(db_path)
        await db.connect()

        state.job_queue = JobQueue(
            db=db,
            max_concurrent=1,
            on_job_update=_on_job_update,
            on_screenshot=_on_screenshot,
        )

        logger.info(f"Job queue initialized at {db_path}")
    except Exception as e:
        logger.warning(f"Failed to initialize job queue: {e}")

    # Initialize and start job runner
    try:
        from ..jobs import JobRunner
        from ..orchestrator import Config, Graboid

        config = Config()
        graboid = Graboid(config)

        state.job_runner = JobRunner(
            queue=state.job_queue,
            graboid=graboid,
            config=config,
            on_screenshot=_runner_screenshot_callback,
        )
        await state.job_runner.start()
        logger.info("Job runner started")
    except Exception as e:
        logger.warning(f"Failed to start job runner: {e}")

    # Load or generate API key
    config_dict = load_config_as_dict()
    api_key = config_dict.get("api", {}).get("api_key", "")
    if not api_key:
        api_key = os.environ.get("GRABOID_API_KEY", "")
    if not api_key:
        api_key = generate_api_key()
        logger.info(f"Generated new API key: {api_key}")
        # Save to config file for persistence
        _save_api_key_to_config(api_key)
    state.api_key = api_key

    # Make state accessible via app.state for API routes
    app.state.job_queue = state.job_queue
    app.state.credential_store = state.credential_store
    app.state.api_key = state.api_key


@app.on_event("shutdown")
async def shutdown_event():
    """Clean up on shutdown."""
    if state.job_runner:
        await state.job_runner.stop()
    if state.job_queue:
        await state.job_queue.shutdown()
        await state.job_queue.db.close()


async def _on_job_update(job):
    """Callback when a job is updated."""
    await state.broadcast({
        "type": "job_update",
        "job_id": job.id,
        "status": job.status.value,
        "progress": job.progress_percent,
        "message": job.progress_message,
    })


async def _on_screenshot(screenshot):
    """Callback when a screenshot is added to the database."""
    await state.broadcast({
        "type": "job_screenshot",
        "job_id": screenshot.job_id,
        "url": screenshot.url,
        "phase": screenshot.phase,
    })


async def _runner_screenshot_callback(job_id: str, screenshot_data: bytes, url: str):
    """Callback from job runner when a screenshot is captured.

    Note: Screenshot is already saved to DB by the runner via queue.add_screenshot.
    This callback just broadcasts to websockets for real-time updates.
    """
    await state.broadcast({
        "type": "job_screenshot",
        "job_id": job_id,
        "url": url,
        "has_data": True,
    })


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
        self.api_key: str = ""
        self.job_queue = None  # Initialized in startup
        self.job_runner = None  # Initialized in startup
        self.credential_store = None  # Initialized in startup
        self.graboid = None  # Initialized in startup

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


def _save_api_key_to_config(api_key: str) -> None:
    """Save API key to config file, preserving other settings."""
    path = find_config_file() or CONFIG_SEARCH_PATHS[0]

    # Load existing config or start fresh
    config_dict = {}
    if path.exists():
        with open(path, "rb") as f:
            config_dict = tomllib.load(f)

    # Update api section
    if "api" not in config_dict:
        config_dict["api"] = {}
    config_dict["api"]["api_key"] = api_key

    # Write back as TOML
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w") as f:
        for section, values in config_dict.items():
            if isinstance(values, dict):
                f.write(f"[{section}]\n")
                for key, value in values.items():
                    if isinstance(value, bool):
                        f.write(f"{key} = {str(value).lower()}\n")
                    elif isinstance(value, str):
                        f.write(f'{key} = "{value}"\n')
                    elif isinstance(value, list):
                        items = ", ".join(f'"{v}"' if isinstance(v, str) else str(v) for v in value)
                        f.write(f"{key} = [{items}]\n")
                    else:
                        f.write(f"{key} = {value}\n")
                f.write("\n")
            else:
                # Top-level key
                if isinstance(values, bool):
                    f.write(f"{section} = {str(values).lower()}\n")
                elif isinstance(values, str):
                    f.write(f'{section} = "{values}"\n')
                else:
                    f.write(f"{section} = {values}\n")

    logger.info(f"Saved API key to {path}")


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
async def save_config_form(request: Request):
    """Save configuration."""
    user = get_current_user(request)
    if not user:
        return RedirectResponse(url="/login", status_code=303)

    # Parse form data manually to handle checkbox correctly
    form = await request.form()

    # Parse path mappings (one per line)
    path_mappings_raw = form.get("path_mappings", "")
    mappings = [m.strip() for m in path_mappings_raw.split("\n") if m.strip()]

    # Checkbox is present in form only when checked
    headless = "headless" in form

    config_data = {
        "llm_provider": form.get("llm_provider", "claude_code"),
        "llm_model": form.get("llm_model", "sonnet"),
        "browser_mode": form.get("browser_mode", "chrome"),
        "torrent_client": form.get("torrent_client", "embedded"),
        "qbittorrent_host": form.get("qbittorrent_host", "localhost"),
        "qbittorrent_port": int(form.get("qbittorrent_port", 8080)),
        "qbittorrent_username": form.get("qbittorrent_username", "admin"),
        "qbittorrent_password": form.get("qbittorrent_password", "adminadmin"),
        "path_mappings": mappings,
        "download_dir": form.get("download_dir", "./downloads"),
        "headless": headless,
        "log_level": form.get("log_level", "INFO"),
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


@app.get("/jobs", response_class=HTMLResponse)
async def jobs_page(request: Request):
    """Job queue management page."""
    user = get_current_user(request)
    if not user:
        return RedirectResponse(url="/login", status_code=303)

    jobs = []
    if state.job_queue:
        jobs = await state.job_queue.list_jobs(limit=50)

    return templates.TemplateResponse("jobs.html", {
        "request": request,
        "user": user,
        "jobs": jobs,
        "api_key": state.api_key,
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


@app.post("/api/test/torrent")
async def test_torrent_connection(request: Request):
    """Test torrent client connectivity using form values."""
    user = get_current_user(request)
    if not user:
        return {"success": False, "error": "Not authenticated"}

    try:
        from ..torrent import QBittorrentClient, TransmissionClient, Aria2Client

        # Get values from form body
        form = await request.form()
        client_type = form.get("torrent_client", "qbittorrent")

        client = None
        if client_type == "qbittorrent":
            client = QBittorrentClient(
                host=form.get("qbittorrent_host", "localhost"),
                port=int(form.get("qbittorrent_port", 8080)),
                username=form.get("qbittorrent_username", "admin"),
                password=form.get("qbittorrent_password", "adminadmin"),
            )
        elif client_type == "transmission":
            client = TransmissionClient(
                host=form.get("transmission_host", "localhost"),
                port=int(form.get("transmission_port", 9091)),
            )
        elif client_type == "aria2":
            client = Aria2Client(
                host=form.get("aria2_host", "localhost"),
                port=int(form.get("aria2_port", 6800)),
                secret=form.get("aria2_secret", ""),
            )

        if client:
            if await client.is_available():
                torrents = await client.list_torrents()
                return {
                    "success": True,
                    "message": f"Connected to {client_type}. {len(torrents)} active torrents.",
                }
            else:
                return {"success": False, "error": f"Could not connect to {client_type}"}
        else:
            return {"success": False, "error": f"Test not implemented for {client_type}"}

    except Exception as e:
        return {"success": False, "error": str(e)}


@app.post("/api/test/llm")
async def test_llm_connection(request: Request):
    """Test LLM provider connectivity using form values."""
    user = get_current_user(request)
    if not user:
        return {"success": False, "error": "Not authenticated"}

    try:
        form = await request.form()
        provider = form.get("llm_provider", "claude_code")
        model = form.get("llm_model", "sonnet")

        if provider == "claude_code":
            from ..browser.claude_code_llm import ClaudeCodeChat
            chat = ClaudeCodeChat(model=model, timeout=30)
            messages = [{"role": "user", "content": "Respond with exactly: OK"}]
            result = await chat.ainvoke(messages)
            if result and result.content:
                return {
                    "success": True,
                    "message": f"Claude Code ({model}) connected. Response: {result.content[:50]}",
                }
            return {"success": False, "error": "Empty response"}

        elif provider == "ollama":
            import httpx
            host = form.get("ollama_host", "http://localhost:11434")
            async with httpx.AsyncClient() as client:
                resp = await client.get(f"{host}/api/tags", timeout=10)
                if resp.status_code == 200:
                    models = resp.json().get("models", [])
                    return {
                        "success": True,
                        "message": f"Ollama connected. {len(models)} models available.",
                    }
                return {"success": False, "error": f"HTTP {resp.status_code}"}

        else:
            # For API-key based providers, just check if key exists
            import os
            key_map = {
                "anthropic": "ANTHROPIC_API_KEY",
                "openai": "OPENAI_API_KEY",
                "google": "GOOGLE_API_KEY",
                "openrouter": "OPENROUTER_API_KEY",
            }
            key_name = key_map.get(provider)
            if key_name and os.getenv(key_name):
                return {
                    "success": True,
                    "message": f"{provider} API key found ({key_name})",
                }
            elif key_name:
                return {"success": False, "error": f"Missing {key_name} environment variable"}
            else:
                return {"success": False, "error": f"Unknown provider: {provider}"}

    except Exception as e:
        return {"success": False, "error": str(e)}


@app.get("/api/ollama/models")
async def get_ollama_models(request: Request):
    """Get available Ollama models."""
    try:
        import httpx
        config = load_config_as_dict()
        host = config.get("ollama_host", "http://localhost:11434")
        async with httpx.AsyncClient() as client:
            resp = await client.get(f"{host}/api/tags", timeout=5)
            if resp.status_code == 200:
                data = resp.json()
                models = [m.get("name", "") for m in data.get("models", [])]
                return {"models": models}
    except Exception:
        pass
    return {"models": []}


@app.get("/api/claude/models")
async def get_claude_models(request: Request):
    """Get available Claude models by asking Claude CLI."""
    import asyncio

    # File-based cache that persists across restarts (OS-appropriate location)
    cache_dir = Path(user_cache_dir("graboid", "graboid"))
    cache_file = cache_dir / "claude_models_cache.json"
    cache_max_age = 86400  # 24 hours

    # Try to load from file cache first
    try:
        if cache_file.exists():
            data = json.loads(cache_file.read_text())
            if time.time() - data.get("timestamp", 0) < cache_max_age:
                return {"models": data.get("models", [])}
    except Exception:
        pass

    # Fetch from Claude CLI
    try:
        proc = await asyncio.create_subprocess_exec(
            "claude", "-p",
            "List all available Claude model IDs. Return ONLY a comma-separated list of model IDs, nothing else. Include aliases like sonnet, opus, haiku first.",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=60)

        if proc.returncode == 0:
            text = stdout.decode().strip()
            models = [m.strip() for m in text.split(",") if m.strip()]
            # Save to file cache
            try:
                cache_file.parent.mkdir(parents=True, exist_ok=True)
                cache_file.write_text(json.dumps({"timestamp": time.time(), "models": models}))
            except Exception:
                pass
            return {"models": models}
    except Exception as e:
        logger.debug(f"Failed to get Claude models: {e}")

    # Fallback to hardcoded list
    fallback = ["sonnet", "opus", "haiku", "claude-opus-4-5-20251101", "claude-sonnet-4-20250514", "claude-haiku-3-5-20241022"]
    return {"models": fallback}


@app.get("/api/notes/stats")
async def get_notes_stats():
    """Get notes statistics."""
    notes_db = get_notes_db()
    return notes_db.get_stats()


@app.get("/api/logs")
async def get_logs(limit: int = 100, level: str = None, search: str = None):
    """Get recent logs from memory buffer."""
    logs = list(log_buffer)

    # Filter by level
    if level:
        level_upper = level.upper()
        logs = [l for l in logs if l["level"] == level_upper]

    # Filter by search term
    if search:
        search_lower = search.lower()
        logs = [l for l in logs if search_lower in l["message"].lower()]

    # Return most recent
    return {"logs": logs[-limit:]}


def get_app_state() -> AppState:
    """Get the global app state for use by other modules."""
    return state


DEFAULT_PORT = 8742  # Graboid default port


def run_server(host: str = "127.0.0.1", port: int = DEFAULT_PORT):
    """Run the web server."""
    import uvicorn
    uvicorn.run(app, host=host, port=port)
