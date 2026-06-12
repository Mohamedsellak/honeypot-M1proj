"""Honeypot FTP (B8) avec pyftpdlib + faux filesystem.

Accepte (presque) toutes les connexions, logge USER/PASS/LIST/RETR, et expose
un faux filesystem appatant (secrets.txt, backup.zip, db_dump.sql).
Banniere: 220 (vsFTPd 3.0.5) (B19).
"""

from __future__ import annotations

import os
import sys
import tempfile
import uuid
from pathlib import Path

from pyftpdlib.authorizers import DummyAuthorizer
from pyftpdlib.handlers import FTPHandler
from pyftpdlib.servers import FTPServer

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "common"))
from hp_common import emit, make_event  # noqa: E402

PORT = int(os.environ.get("HP_FTP_PORT", "2121"))
BANNER = os.environ.get("HP_FTP_BANNER", "220 (vsFTPd 3.0.5)")

LURE_FILES = {
    "secrets.txt": "db_root_password=Pr0d!2024#db\napi_key=sk-live-9f8a7b6c5d4e3f2a1b0c\n",
    "db_dump.sql": "-- MySQL dump 10.13\nINSERT INTO users VALUES (1,'admin','5f4dcc3b5aa765d61d8327deb882cf99');\n",
    "README.txt": "Backups quotidiens. Ne pas supprimer. Contact: ops@corp.internal\n",
}


def _build_fake_root() -> str:
    root = Path(tempfile.mkdtemp(prefix="ftp-honey-"))
    for name, content in LURE_FILES.items():
        (root / name).write_text(content, encoding="utf-8")
    (root / "backup.zip").write_bytes(b"PK\x03\x04fake-archive-content-do-not-trust")
    return str(root)


def _peer(handler: FTPHandler) -> tuple[str, int | None]:
    try:
        return handler.remote_ip, handler.remote_port
    except AttributeError:
        return "0.0.0.0", None


class HoneypotFTPHandler(FTPHandler):
    banner = BANNER

    def on_connect(self) -> None:
        ip, port = _peer(self)
        self._session_id = str(uuid.uuid4())
        emit(make_event("ftp", ip, "connect", session_id=self._session_id,
                        src_port=port, dst_port=PORT))

    def on_login(self, username: str) -> None:
        ip, port = _peer(self)
        emit(make_event("ftp", ip, "login_attempt", session_id=getattr(self, "_session_id", None),
                        src_port=port, dst_port=PORT, username=username,
                        password=getattr(self, "_last_pass", None),
                        ftp={"result": "success"}))

    def on_login_failed(self, username: str, password: str) -> None:
        ip, port = _peer(self)
        emit(make_event("ftp", ip, "login_attempt", session_id=getattr(self, "_session_id", None),
                        src_port=port, dst_port=PORT, username=username, password=password,
                        ftp={"result": "failed"}))

    def ftp_PASS(self, line: str):  # noqa: N802 - nom impose par pyftpdlib
        self._last_pass = line
        return super().ftp_PASS(line)

    def ftp_RETR(self, file: str):  # noqa: N802
        ip, port = _peer(self)
        emit(make_event("ftp", ip, "file_download", session_id=getattr(self, "_session_id", None),
                        src_port=port, dst_port=PORT, ftp={"cmd": "RETR", "file": file}))
        return super().ftp_RETR(file)

    def ftp_LIST(self, path: str):  # noqa: N802
        ip, port = _peer(self)
        emit(make_event("ftp", ip, "ftp_cmd", session_id=getattr(self, "_session_id", None),
                        src_port=port, dst_port=PORT, ftp={"cmd": "LIST", "path": path}))
        return super().ftp_LIST(path)


def main() -> None:
    fake_root = _build_fake_root()
    authorizer = DummyAuthorizer()
    # 'anonymous' + un compte appatant ; le bruteforce est logge via on_login_failed.
    authorizer.add_anonymous(fake_root, perm="elr")
    authorizer.add_user("admin", "admin", fake_root, perm="elradfmw")

    handler = HoneypotFTPHandler
    handler.authorizer = authorizer
    handler.passive_ports = range(60000, 60010)

    server = FTPServer(("0.0.0.0", PORT), handler)
    print(f"[honeypot-ftp] listening on 0.0.0.0:{PORT} as {BANNER}", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
