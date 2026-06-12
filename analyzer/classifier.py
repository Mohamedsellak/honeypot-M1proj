"""Moteur de classification comportementale heuristique (B14).

Classifie une *session* (ensemble d'evenements partageant un session_id) dans
l'un des 4 profils definis dans profiles.json :
    - bruteforcer
    - bot
    - human
    - scanner_legitimate

La methode retourne le profil + un score de confiance + les raisons, ce qui
alimente la matrice de confusion mesuree en B14 et le mapping MITRE ATT&CK.
"""

from __future__ import annotations

import json
from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import Any

_PROFILES_PATH = Path(__file__).resolve().parent / "profiles.json"

# Mapping indicatif vers MITRE ATT&CK (utile pour la restitution / exports).
ATTACK_TECHNIQUES = {
    "bruteforcer": ["T1110 Brute Force"],
    "bot": ["T1595 Active Scanning", "T1190 Exploit Public-Facing Application"],
    "human": ["T1059 Command and Scripting Interpreter", "T1083 File and Directory Discovery"],
    "scanner_legitimate": ["T1595 Active Scanning"],
}


class BehaviorClassifier:
    def __init__(self, profiles_path: Path | str = _PROFILES_PATH) -> None:
        self.profiles = json.loads(Path(profiles_path).read_text(encoding="utf-8"))

    # --- helpers --------------------------------------------------------
    @staticmethod
    def _duration_minutes(events: list[dict[str, Any]]) -> float:
        stamps = []
        for event in events:
            try:
                stamps.append(datetime.fromisoformat(event["timestamp"]))
            except (KeyError, ValueError):
                continue
        if len(stamps) < 2:
            return 0.0
        return max((max(stamps) - min(stamps)).total_seconds() / 60.0, 0.0)

    @staticmethod
    def _user_agents(events: list[dict[str, Any]]) -> list[str]:
        agents = []
        for event in events:
            http = event.get("http") or {}
            ua = (http.get("user_agent") or "").lower()
            if ua:
                agents.append(ua)
        return agents

    # --- classification -------------------------------------------------
    def classify_session(self, events: list[dict[str, Any]]) -> dict[str, Any]:
        if not events:
            return {"profile": "unknown", "confidence": 0.0, "reasons": ["session vide"]}

        reasons: list[str] = []
        actions = Counter(e.get("action") for e in events)
        login_attempts = actions.get("login_attempt", 0)
        commands = [e.get("command") for e in events if e.get("action") == "command" and e.get("command")]
        http_events = [e for e in events if e.get("service") == "http"]
        agents = self._user_agents(events)
        duration = self._duration_minutes(events)

        # 1) scanner legitime : UA de scanner connu, volume faible, pas de bruteforce
        cfg_scan = self.profiles["scanner_legitimate"]
        if login_attempts == 0 and len(events) <= cfg_scan["max_events"]:
            for ua in agents:
                if any(known in ua for known in cfg_scan["known_scanners"]):
                    return self._result("scanner_legitimate", 0.95,
                                        [f"user-agent scanner connu: {ua}"])

        # 2) bruteforcer : beaucoup de tentatives d'auth
        cfg_bf = self.profiles["bruteforcer"]
        rate = (login_attempts / duration) if duration > 0 else float(login_attempts)
        if login_attempts >= cfg_bf["min_login_attempts"]:
            reasons.append(f"{login_attempts} tentatives d'authentification")
            if rate >= cfg_bf["min_attempts_per_minute"] or duration == 0:
                reasons.append(f"rythme {rate:.1f}/min")
            confidence = min(0.6 + login_attempts / 200.0, 0.99)
            return self._result("bruteforcer", confidence, reasons)

        # 3) bot : UA automatise OU chemins/payloads d'exploit
        cfg_bot = self.profiles["bot"]
        automated = [ua for ua in agents
                     if any(sig in ua for sig in cfg_bot["automated_user_agents"])]
        exploit_hits = []
        for event in http_events:
            http = event.get("http") or {}
            path = (http.get("path") or "").lower()
            body = (http.get("body") or "").lower()
            if any(p in path for p in cfg_bot["exploit_paths"]):
                exploit_hits.append(path)
            if any(m in body or m in path for m in cfg_bot["exploit_payload_markers"]):
                exploit_hits.append("payload:" + path)
        if automated:
            reasons.append(f"user-agent automatise: {automated[0]}")
        if exploit_hits:
            reasons.append(f"chemins/payloads d'exploit: {sorted(set(exploit_hits))[:5]}")
        if (automated or exploit_hits) and len(events) >= cfg_bot["min_requests"]:
            confidence = 0.75 + 0.05 * min(len(exploit_hits), 4)
            return self._result("bot", min(confidence, 0.98), reasons)

        # 4) human : session shell interactive variee
        cfg_human = self.profiles["human"]
        distinct = len(set(commands))
        if (len(commands) >= cfg_human["min_shell_commands"]
                and distinct >= cfg_human["min_distinct_commands"]):
            cmd_rate = (len(commands) / duration) if duration > 0 else float(len(commands))
            if cmd_rate <= cfg_human["max_commands_per_minute"]:
                reasons.append(f"{len(commands)} commandes shell ({distinct} distinctes)")
                return self._result("human", 0.8, reasons)
            reasons.append("commandes shell a rythme machine")
            return self._result("bot", 0.7, reasons)

        # Fallback : signaux faibles
        if automated or exploit_hits:
            return self._result("bot", 0.55, reasons or ["signaux bot faibles"])
        if login_attempts > 0:
            return self._result("bruteforcer", 0.5, [f"{login_attempts} tentative(s) d'auth"])
        return self._result("scanner_legitimate", 0.4, ["reconnaissance passive, volume faible"])

    @staticmethod
    def _result(profile: str, confidence: float, reasons: list[str]) -> dict[str, Any]:
        return {
            "profile": profile,
            "confidence": round(confidence, 2),
            "reasons": reasons,
            "mitre_attack": ATTACK_TECHNIQUES.get(profile, []),
        }


if __name__ == "__main__":
    import sys
    clf = BehaviorClassifier()
    data = json.loads(Path(sys.argv[1]).read_text()) if len(sys.argv) > 1 else []
    print(json.dumps(clf.classify_session(data), indent=2, ensure_ascii=False))
