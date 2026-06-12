"""Honeypot HTTP (B7) avec FastAPI.

Routes piegees credibles : /admin, /wp-login.php, /.env, /api/v1/users,
/.git/config, /phpinfo.php + catch-all. Chaque requete (methode, path, headers,
UA, body) est loggee. Banniere Server: Apache/2.4.57 (Debian) (B19).
"""

from __future__ import annotations

import os
import sys
import uuid
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse, Response

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "common"))
from hp_common import emit, make_event  # noqa: E402

SERVER_BANNER = os.environ.get("HP_HTTP_BANNER", "Apache/2.4.57 (Debian)")
DST_PORT = int(os.environ.get("HP_HTTP_PORT", "8080"))

app = FastAPI(title="corp-intranet", docs_url=None, redoc_url=None, openapi_url=None)


def _session_id(request: Request) -> str:
    # une session = (ip, user-agent) sur une fenetre courte ; simplification : ip
    return f"http-{request.client.host if request.client else 'unknown'}"


@app.middleware("http")
async def log_requests(request: Request, call_next):
    body_bytes = await request.body()
    body = body_bytes.decode("utf-8", "replace")[:4096] if body_bytes else None
    src_ip = request.client.host if request.client else "0.0.0.0"
    src_port = request.client.port if request.client else None
    emit(make_event(
        "http", src_ip, "request",
        session_id=_session_id(request), src_port=src_port, dst_port=DST_PORT,
        http={
            "method": request.method,
            "path": str(request.url.path) + (("?" + request.url.query) if request.url.query else ""),
            "user_agent": request.headers.get("user-agent"),
            "headers": dict(request.headers),
            "body": body,
        },
    ))
    response = await call_next(request)
    response.headers["Server"] = SERVER_BANNER
    response.headers["X-Powered-By"] = "PHP/8.1.2"
    return response


@app.get("/", response_class=HTMLResponse)
async def index() -> str:
    return "<html><head><title>Intranet</title></head><body><h1>It works!</h1></body></html>"


@app.api_route("/admin", methods=["GET", "POST"], response_class=HTMLResponse)
@app.api_route("/wp-login.php", methods=["GET", "POST"], response_class=HTMLResponse)
async def login_portal() -> str:
    return ("<html><body><h2>Administration</h2>"
            "<form method='post'><input name='log' placeholder='Username'>"
            "<input name='pwd' type='password'><button>Log In</button></form></body></html>")


@app.get("/.env", response_class=PlainTextResponse)
async def dotenv() -> str:
    return ("APP_ENV=production\nAPP_KEY=base64:Xj3kF9mWq2pL8sT1vYbN4zR6dC0eH7gA=\n"
            "DB_CONNECTION=mysql\nDB_HOST=127.0.0.1\nDB_DATABASE=corp_prod\n"
            "DB_USERNAME=corp_admin\nDB_PASSWORD=Pr0d!2024#db\n")


@app.get("/.git/config", response_class=PlainTextResponse)
async def git_config() -> str:
    return ("[core]\n\trepositoryformatversion = 0\n[remote \"origin\"]\n"
            "\turl = git@gitlab.internal:corp/intranet.git\n")


@app.get("/phpinfo.php", response_class=HTMLResponse)
async def phpinfo() -> str:
    return "<html><body><h1>PHP Version 8.1.2</h1><table><tr><td>System</td><td>Linux Debian</td></tr></table></body></html>"


@app.get("/api/v1/users", response_class=JSONResponse)
async def api_users() -> JSONResponse:
    return JSONResponse({"error": "unauthorized", "message": "missing bearer token"}, status_code=401)


@app.api_route("/{full_path:path}",
               methods=["GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH"])
async def catch_all(full_path: str) -> Response:
    return PlainTextResponse("Not Found", status_code=404)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=DST_PORT, server_header=False, log_level="warning")
