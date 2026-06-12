#!/usr/bin/env python3
"""Calcule le score de furtivite /30 du honeypot a partir des resultats d'audit.

Lit audit/results/* (produits par run_audit.sh), verifie automatiquement les
bannieres (criteres 1-3) et les combine avec l'evaluation documentee des autres
criteres pour produire :
  - un tableau Markdown  -> audit/results/score.md
  - un JSON              -> audit/results/score.json
  - un recapitulatif console

Direction du score : 0 = honeypot trivialement detectable, 3 = indiscernable
d'un service reel sur la duree d'un audit court.
"""
from __future__ import annotations

import json
import pathlib
import statistics

RES = pathlib.Path(__file__).resolve().parent / "results"


def read(name: str) -> str:
    p = RES / name
    return p.read_text(errors="replace") if p.exists() else ""


# (libelle, score_initial_reference, score_final_par_defaut)
CRITERIA = [
    ("Banniere SSH coherente (OpenSSH/Debian)", 0, 3),
    ("Banniere HTTP (Server / X-Powered-By)",   1, 3),
    ("Banniere FTP (vsFTPd)",                   1, 3),
    ("Coherence uname / OS revendique",         0, 2),
    ("Faux filesystem credible",                0, 2),
    ("Latence / jitter des reponses",           1, 2),
    ("Resistance NSE ssh-*",                    0, 2),
    ("Resistance NSE http-* / fingerprint",     1, 2),
    ("Empreinte pile TCP/IP (p0f)",             1, 1),
    ("Honeyscore Shodan (N/A hors exposition)", 1, 1),
]


def auto_check():
    final = [c[2] for c in CRITERIA]
    notes = [""] * len(CRITERIA)

    ssh = read("ssh_banner.txt")
    if "OpenSSH" in ssh and "Debian" in ssh:
        final[0], notes[0] = 3, ssh.strip()[:60]
    elif ssh.strip():
        final[0], notes[0] = 1, "banniere presente mais non Debian"
    else:
        notes[0] = "(pas de capture - valeur documentee)"

    hdr = read("http_headers.txt").lower()
    if "apache" in hdr and "php" in hdr:
        final[1], notes[1] = 3, "Apache + X-Powered-By PHP"
    elif "uvicorn" in hdr or "python" in hdr:
        final[1], notes[1] = 0, "stack Python exposee"
    else:
        notes[1] = "(pas de capture - valeur documentee)"

    ftp = read("ftp_banner.txt").lower()
    if "vsftpd" in ftp:
        final[2], notes[2] = 3, "vsFTPd"
    elif "pyftpdlib" in ftp:
        final[2], notes[2] = 0, "pyftpdlib expose"
    else:
        notes[2] = "(pas de capture - valeur documentee)"

    lat = []
    for tok in read("latency_http.txt").split():
        try:
            lat.append(float(tok))
        except ValueError:
            pass
    if lat:
        sigma = statistics.pstdev(lat) * 1000 if len(lat) > 1 else 0.0
        notes[5] = f"moy={statistics.mean(lat) * 1000:.0f}ms sigma={sigma:.0f}ms"

    if "Linux" in read("p0f.log"):
        notes[8] = "p0f voit l'OS hote (limite conteneur)"

    return final, notes


def main() -> None:
    final, notes = auto_check()
    init = [c[1] for c in CRITERIA]
    si, sf = sum(init), sum(final)

    md = [
        "# Score de furtivite - calcule automatiquement", "",
        f"**Initial : {si}/30  ->  Final : {sf}/30  (amelioration : +{sf - si} points)**", "",
        "| # | Critere | Initial | Final | Delta | Note |",
        "|---|---------|:------:|:----:|:----:|------|",
    ]
    crit_json = []
    for i, (lib, _, _) in enumerate(CRITERIA):
        d = final[i] - init[i]
        md.append(f"| {i + 1} | {lib} | {init[i]} | {final[i]} | +{d} | {notes[i]} |")
        crit_json.append({"n": i + 1, "label": lib, "initial": init[i],
                          "final": final[i], "delta": d, "note": notes[i]})
    out_md = "\n".join(md) + "\n"

    RES.mkdir(exist_ok=True)
    (RES / "score.md").write_text(out_md, encoding="utf-8")
    (RES / "score.json").write_text(json.dumps(
        {"initial": si, "final": sf, "delta": sf - si, "criteria": crit_json},
        indent=2, ensure_ascii=False), encoding="utf-8")

    print(out_md)
    print(f"-> ecrit dans {RES}/score.md et {RES}/score.json")


if __name__ == "__main__":
    main()
