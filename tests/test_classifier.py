"""Tests + matrice de confusion du classifier (B14)."""

import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "analyzer"))

from classifier import BehaviorClassifier  # noqa: E402

CLF = BehaviorClassifier()


def _ts(offset_s=0):
    return (datetime.now(timezone.utc) + timedelta(seconds=offset_s)).isoformat()


def _bruteforce_session(n=30):
    return [{"service": "ssh", "action": "login_attempt", "timestamp": _ts(i),
             "username": "root", "password": f"p{i}", "session_id": "s1"} for i in range(n)]


def _bot_session():
    return [{"service": "http", "action": "request", "timestamp": _ts(i),
             "http": {"path": p, "user_agent": "python-requests/2.31", "headers": {}}}
            for i, p in enumerate(["/.env", "/wp-login.php", "/.git/config", "/admin"])]


def _human_session():
    cmds = ["whoami", "ls -la", "cat /etc/passwd", "uname -a", "ps aux"]
    return [{"service": "ssh", "action": "command", "timestamp": _ts(i * 8),
             "command": c, "session_id": "h1"} for i, c in enumerate(cmds)]


def _scanner_session():
    return [{"service": "http", "action": "request", "timestamp": _ts(),
             "http": {"path": "/", "user_agent": "Mozilla/5.0 (compatible; CensysInspect/1.1)",
                      "headers": {}}}]


def test_bruteforcer():
    assert CLF.classify_session(_bruteforce_session())["profile"] == "bruteforcer"


def test_bot():
    assert CLF.classify_session(_bot_session())["profile"] == "bot"


def test_human():
    assert CLF.classify_session(_human_session())["profile"] == "human"


def test_scanner_legitimate():
    assert CLF.classify_session(_scanner_session())["profile"] == "scanner_legitimate"


def test_confusion_matrix_accuracy():
    cases = {
        "bruteforcer": _bruteforce_session,
        "bot": _bot_session,
        "human": _human_session,
        "scanner_legitimate": _scanner_session,
    }
    correct = sum(1 for label, gen in cases.items()
                  if CLF.classify_session(gen())["profile"] == label)
    assert correct / len(cases) >= 0.85  # precision > 85% (objectif B14)
