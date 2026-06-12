"""Faux shell SSH credible (B6 + B20/B21).

Repond comme un vrai serveur Debian 12 : whoami, ls, cat /etc/passwd, uname -a,
id, pwd, history, ps aux, netstat, /proc/cpuinfo... + faux filesystem riche.
Objectif : un audit manuel de ~10 min ne doit pas trahir le honeypot.
"""

from __future__ import annotations

HOSTNAME = "srv-prod-debian"

_PASSWD = """root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
postgres:x:114:120:PostgreSQL administrator,,,:/var/lib/postgresql:/bin/bash
admin:x:1000:1000:admin,,,:/home/admin:/bin/bash"""

_CPUINFO = """processor\t: 0
vendor_id\t: GenuineIntel
model name\t: Intel(R) Xeon(R) CPU E5-2670 v3 @ 2.30GHz
cpu cores\t: 4
cache size\t: 30720 KB
"""

_PS_AUX = """USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
root         1  0.0  0.1 169284 11876 ?       Ss   Apr10   0:12 /sbin/init
root       412  0.0  0.0  72308  6540 ?       Ss   Apr10   0:00 /usr/sbin/sshd -D
postgres   801  0.0  0.6 218104 49152 ?       S    Apr10   1:43 postgres: main
www-data   902  0.0  0.2 145320 18204 ?       S    Apr10   0:21 nginx: worker
admin     2451  0.0  0.0  21532  5120 pts/0    Ss   10:01   0:00 -bash"""

_NETSTAT = """Active Internet connections (servers and established)
Proto Recv-Q Send-Q Local Address           Foreign Address         State
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN
tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN
tcp        0      0 127.0.0.1:5432          0.0.0.0:*               LISTEN"""

_BASH_HISTORY = """ls -la
cd /var/www
git pull
sudo apt update
docker ps
vim config.yml
npm install
systemctl restart nginx
psql -U postgres
htop"""

_LS_HOME = "Documents  projects  backup.sql  .bashrc  .profile  .ssh"


class FakeShell:
    """Etat minimal d'un shell ; .run(cmd) renvoie la sortie (ou None pour exit)."""

    def __init__(self, username: str = "root") -> None:
        self.username = username or "root"
        self.cwd = "/root" if self.username == "root" else f"/home/{self.username}"

    def prompt(self) -> str:
        symbol = "#" if self.username == "root" else "$"
        return f"{self.username}@{HOSTNAME}:{self.cwd}{symbol} "

    def banner(self) -> str:
        return (
            "Linux srv-prod-debian 6.1.0-18-amd64 #1 SMP PREEMPT_DYNAMIC Debian "
            "6.1.76-1 x86_64\n"
            "The programs included with the Debian GNU/Linux system are free software.\n"
            f"Last login: Mon Jun  9 09:14:02 2025 from 10.0.0.42\n"
        )

    def run(self, line: str) -> str | None:
        cmd = line.strip()
        if not cmd:
            return ""
        if cmd in ("exit", "logout", "quit"):
            return None
        argv = cmd.split()
        base = argv[0]

        table = {
            "whoami": self.username,
            "id": f"uid=0(root) gid=0(root) groups=0(root)" if self.username == "root"
                  else "uid=1000(admin) gid=1000(admin) groups=1000(admin),27(sudo)",
            "pwd": self.cwd,
            "hostname": HOSTNAME,
            "uname": self._uname(argv),
            "history": _BASH_HISTORY,
            "ps": _PS_AUX,
            "netstat": _NETSTAT,
            "ss": _NETSTAT,
            "who": f"{self.username}   pts/0        2025-06-09 09:14 (10.0.0.42)",
            "last": f"{self.username}   pts/0   10.0.0.42   Mon Jun  9 09:14   still logged in",
            "date": "Mon Jun  9 10:32:11 UTC 2025",
            "ls": _LS_HOME,
            "uptime": " 10:32:11 up 61 days,  2:18,  1 user,  load average: 0.08, 0.03, 0.01",
        }
        if base in table and base != "uname":
            return str(table[base])
        if base == "uname":
            return self._uname(argv)
        if base == "cat":
            return self._cat(argv)
        if base == "cd":
            self.cwd = argv[1] if len(argv) > 1 else ("/root" if self.username == "root"
                                                      else f"/home/{self.username}")
            return ""
        if base == "echo":
            return " ".join(argv[1:])
        if base in ("sudo", "su"):
            return "Sorry, user may not run sudo on this host." if base == "sudo" else \
                   "su: Authentication failure"
        if base in ("wget", "curl"):
            return f"--2025-06-09 10:32:14--  {argv[-1] if len(argv) > 1 else ''}\nResolving host... failed: Temporary failure in name resolution."
        # commande inconnue -> comportement bash plausible
        return f"-bash: {base}: command not found"

    def _uname(self, argv: list[str]) -> str:
        if "-a" in argv:
            return ("Linux srv-prod-debian 6.1.0-18-amd64 #1 SMP PREEMPT_DYNAMIC "
                    "Debian 6.1.76-1 (2024-02-01) x86_64 GNU/Linux")
        return "Linux"

    def _cat(self, argv: list[str]) -> str:
        if len(argv) < 2:
            return ""
        target = argv[1]
        files = {
            "/etc/passwd": _PASSWD,
            "/proc/cpuinfo": _CPUINFO,
            "/etc/hostname": HOSTNAME,
            "/etc/os-release": 'PRETTY_NAME="Debian GNU/Linux 12 (bookworm)"\nVERSION_ID="12"',
            ".bash_history": _BASH_HISTORY,
            "/root/.bash_history": _BASH_HISTORY,
        }
        if target in files:
            return files[target]
        return f"cat: {target}: No such file or directory"
