"""Genere datasets/rockyou-top1000.txt (echantillon representatif).

Le vrai rockyou-top1000 est distribue en J1 par le formateur. Ce generateur
produit une liste credible de ~1000 mots de passe pour faire tourner les
bruteforce de validation sans dependance externe.
"""

from pathlib import Path

BASE = [
    "123456", "password", "123456789", "12345678", "12345", "qwerty", "abc123",
    "football", "1234567", "monkey", "111111", "letmein", "1234", "1234567890",
    "dragon", "baseball", "sunshine", "iloveyou", "trustno1", "princess", "admin",
    "welcome", "666666", "shadow", "superman", "qazwsx", "michael", "football1",
    "root", "toor", "pass", "test", "oracle", "postgres", "ubuntu", "changeme",
    "master", "hello", "login", "passw0rd", "starwars", "whatever", "freedom",
]
SUFFIXES = ["", "1", "123", "!", "2024", "2025", "01", "007", "#1", "@123"]


def main() -> None:
    seen = []
    out = []
    for word in BASE:
        for suf in SUFFIXES:
            cand = word + suf
            if cand not in seen:
                seen.append(cand)
                out.append(cand)
    # complete jusqu'a ~1000 entrees avec des variantes numeriques
    i = 0
    while len(out) < 1000:
        out.append(f"P@ssw0rd{i}")
        i += 1
    Path(__file__).with_name("rockyou-top1000.txt").write_text(
        "\n".join(out[:1000]) + "\n", encoding="utf-8")
    print(f"[+] rockyou-top1000.txt genere ({len(out[:1000])} entrees)")


if __name__ == "__main__":
    main()
