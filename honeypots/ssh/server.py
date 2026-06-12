"""Honeypot SSH medium-interaction (B4 + B6).

- asyncssh, accepte les connexions et CAPTURE chaque couple login/password.
- Quelques credentials "faibles" sont acceptes -> ouvre un faux shell credible.
- Banniere coherente avec une vraie Debian 12 (B19) : SSH-2.0-OpenSSH_9.2p1...

Chaque evenement est ecrit en JSON signe via hp_common.emit().
"""

from __future__ import annotations

import asyncio
import os
import random
import sys
import uuid
from pathlib import Path

import asyncssh

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "common"))
from hp_common import emit, make_event  # noqa: E402

from fakeshell import FakeShell  # noqa: E402

PORT = int(os.environ.get("HP_SSH_PORT", "2222"))
BANNER = os.environ.get("HP_SSH_BANNER", "SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u3")
# asyncssh prefixe AUTOMATIQUEMENT "SSH-2.0-". Il ne faut donc PAS le renvoyer
# nous-memes via server_version, sinon la banniere devient
# "SSH-2.0-SSH-2.0-OpenSSH..." (malformee) et les clients SSH (hydra/libssh)
# ferment immediatement la connexion ("Socket error: disconnected").
_SSH_VERSION = BANNER[len("SSH-2.0-"):] if BANNER.startswith("SSH-2.0-") else BANNER

# Credentials "faibles" acceptes : laisse passer l'attaquant vers le faux shell.
ACCEPTED = {
    ("root", "123456"), ("root", "root"), ("root", "toor"), ("root", "password"),
    ("admin", "admin"), ("admin", "123456"),
}


class HoneypotSSHServer(asyncssh.SSHServer):
    def connection_made(self, conn: asyncssh.SSHServerConnection) -> None:
        self._conn = conn
        peer = conn.get_extra_info("peername") or ("0.0.0.0", None)
        self.src_ip, self.src_port = peer[0], peer[1]
        self.session_id = str(uuid.uuid4())
        emit(make_event("ssh", self.src_ip, "connect",
                        session_id=self.session_id, src_port=self.src_port, dst_port=PORT))

    def begin_auth(self, username: str) -> bool:
        return True  # force l'auth par mot de passe pour capturer les credentials

    def password_auth_supported(self) -> bool:
        return True

    def validate_password(self, username: str, password: str) -> bool:
        emit(make_event("ssh", self.src_ip, "login_attempt",
                        session_id=self.session_id, src_port=self.src_port, dst_port=PORT,
                        username=username, password=password))
        return (username, password) in ACCEPTED


async def handle_session(process: asyncssh.SSHServerProcess) -> None:
    peer = process.get_extra_info("peername") or ("0.0.0.0", None)
    src_ip, src_port = peer[0], peer[1]
    session_id = str(uuid.uuid4())
    username = process.get_extra_info("username") or "root"
    shell = FakeShell(username=username)

    emit(make_event("ssh", src_ip, "shell_open",
                    session_id=session_id, src_port=src_port, dst_port=PORT, username=username))
    process.stdout.write(shell.banner())
    process.stdout.write(shell.prompt())
    try:
        async for line in process.stdin:
            cmd = line.rstrip("\n")
            emit(make_event("ssh", src_ip, "command",
                            session_id=session_id, src_port=src_port, dst_port=PORT,
                            username=username, command=cmd))
            await asyncio.sleep(random.uniform(0.05, 0.30))  # jitter (B21)
            out = shell.run(cmd)
            if out is None:
                process.stdout.write("logout\n")
                break
            if out:
                process.stdout.write(out + "\n")
            process.stdout.write(shell.prompt())
    except (asyncssh.BreakReceived, asyncssh.TerminalSizeChanged):
        pass
    except Exception:  # noqa: BLE001 - ne jamais crasher le honeypot
        pass
    finally:
        process.exit(0)


async def start() -> None:
    key = asyncssh.generate_private_key("ssh-rsa")
    await asyncssh.create_server(
        HoneypotSSHServer, "", PORT,
        server_host_keys=[key],
        process_factory=handle_session,
        server_version=_SSH_VERSION,
    )
    print(f"[honeypot-ssh] listening on 0.0.0.0:{PORT} as {BANNER}", flush=True)
    await asyncio.Future()


if __name__ == "__main__":
    try:
        asyncio.run(start())
    except (OSError, asyncssh.Error) as exc:
        print(f"[honeypot-ssh] fatal: {exc}", file=sys.stderr)
        sys.exit(1)
