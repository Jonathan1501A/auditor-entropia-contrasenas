#!/usr/bin/env python3
"""
Taller de Seguridad en Hacking - Actividad 3
Auditor de Seguridad y Entropía de Contraseñas (Shannon/NIST).
"""

import argparse, getpass, math, re, secrets, string, sys
from dataclasses import dataclass, field
from pathlib import Path

@dataclass
class AuditReport:
    password_length: int
    has_lowercase: bool; has_uppercase: bool; has_digits: bool; has_symbols: bool
    entropy_bits: float; pool_size: int; is_common: bool; has_sequential: bool; has_repeated: bool
    score: int; classification: str; estimated_crack_time: str
    vulnerabilities: list[str] = field(default_factory=list)
    recommendations: list[str] = field(default_factory=list)

class PasswordAuditor:
    SEQS = ["1234567890", "0987654321", "qwertyuiop", "asdfghjkl", "zxcvbnm", "abcdefghijklmnopqrstuvwxyz"]

    def __init__(self, dict_path: str | Path | None = None) -> None:
        self.common: set[str] = set()
        p = Path(dict_path) if dict_path else Path(__file__).parent / "common_passwords.txt"
        if p.exists() and p.is_file():
            self.common = {line.strip().lower() for line in p.read_text(encoding="utf-8", errors="ignore").splitlines() if line.strip()}

    def _calc_pool(self, l: bool, u: bool, d: bool, s: bool) -> int:
        return (26 if l else 0) + (26 if u else 0) + (10 if d else 0) + (32 if s else 0) or 1

    def _crack_time(self, bits: float) -> str:
        if bits <= 0: return "Instantáneo"
        sec = (2 ** bits) / (2 * 100_000_000_000)
        if sec < 0.001: return "Instantáneo (< 1 ms)"
        if sec < 60: return f"{sec:.1f} s"
        if sec < 3600: return f"{sec / 60:.1f} m"
        if sec < 86400: return f"{sec / 3600:.1f} h"
        if sec < 86400 * 365: return f"{sec / 86400:.1f} días"
        return f"{sec / (86400 * 365):.1f} años" if sec < 86400 * 365 * 1000 else "Prácticamente inquebrantable"

    def audit(self, pwd: str) -> AuditReport:
        l, u, d, s = bool(re.search(r"[a-z]", pwd)), bool(re.search(r"[A-Z]", pwd)), bool(re.search(r"[0-9]", pwd)), bool(re.search(r"[^a-zA-Z0-9]", pwd))
        pool = self._calc_pool(l, u, d, s)
        entropy = len(pwd) * math.log2(pool) if len(pwd) > 0 and pool > 1 else 0.0
        pwd_l = pwd.lower()
        is_com = pwd_l in self.common
        has_seq = any(seq[i:i+3] in pwd_l for seq in self.SEQS for i in range(len(seq)-2))
        has_rep = bool(re.search(r"(.)\1{2,}", pwd))

        vulns, recs = [], []
        score = min(100, int((entropy / 80.0) * 100))

        if len(pwd) < 8:
            vulns.append("Longitud crítica (< 8 caracteres).")
            recs.append("Aumenta la longitud a mínimo 12-16 caracteres.")
            score = min(score, 25)
        elif len(pwd) < 12:
            recs.append("Aumenta la longitud a 14+ caracteres para mayor seguridad.")

        if not l: recs.append("Incluye letras minúsculas (a-z).")
        if not u: recs.append("Incluye letras mayúsculas (A-Z).")
        if not d: recs.append("Incluye números (0-9).")
        if not s: recs.append("Incluye símbolos especiales (!@#$...).")

        if is_com:
            vulns.append("Contraseña conocida en listas filtradas.")
            recs.append("No uses palabras o secuencias comunes.")
            score = min(score, 10)
        if has_seq: vulns.append("Patrón secuencial detectado (ej. 123, abc)."); score = max(0, score - 15)
        if has_rep: vulns.append("Caracteres repetidos consecutivos (ej. aaa)."); score = max(0, score - 10)

        clas = "MUY DÉBIL" if score < 25 or is_com or len(pwd) < 6 else "DÉBIL" if score < 50 else "MODERADA" if score < 75 else "FUERTE" if score < 90 else "MUY FUERTE"
        
        return AuditReport(len(pwd), l, u, d, s, round(entropy, 2), pool, is_com, has_seq, has_rep, score, clas, self._crack_time(entropy if not is_com else 5.0), vulns, recs)

    @staticmethod
    def generate_secure_password(length: int = 16) -> str:
        chars = string.ascii_lowercase + string.ascii_uppercase + string.digits + "!@#$%^&*()-_=+[]{}|;:,.<>?"
        while True:
            pwd = "".join(secrets.choice(chars) for _ in range(max(8, length)))
            if (any(c in string.ascii_lowercase for c in pwd) and any(c in string.ascii_uppercase for c in pwd) and any(c in string.digits for c in pwd) and any(c in "^!@#$%^&*()-_=+[]{}|;:,.<>?" for c in pwd)):
                return pwd

def display_report(rep: AuditReport) -> None:
    bar = "#" * int((rep.score / 100) * 30) + "-" * (30 - int((rep.score / 100) * 30))
    print(f"\n{'='*60}\n RESULTADO DE LA AUDITORÍA DE SEGURIDAD\n{'='*60}")
    print(f"Puntuación      : [{bar}] {rep.score}/100\nNivel           : {rep.classification}\nLongitud        : {rep.password_length} caracteres\nEntropía        : {rep.entropy_bits} bits (Espacio: {rep.pool_size})\nTiempo Crack    : {rep.estimated_crack_time}\n{'-'*60}\nCOMPOSICIÓN:")
    print(f"  [{'OK' if rep.has_lowercase else ' X '}] Minúsculas  [{'OK' if rep.has_uppercase else ' X '}] Mayúsculas\n  [{'OK' if rep.has_digits else ' X '}] Números     [{'OK' if rep.has_symbols else ' X '}] Símbolos\n{'-'*60}")
    if rep.vulnerabilities:
        print("VULNERABILIDADES:"); [print(f"  [!] {v}") for v in rep.vulnerabilities]; print("-" * 60)
    if rep.recommendations:
        print("RECOMENDACIONES:"); [print(f"  [+] {r}") for r in rep.recommendations]
    else: print("[+] Contraseña cumple con los estándares de seguridad.")
    print("=" * 60 + "\n")

def main() -> None:
    p = argparse.ArgumentParser(description="Auditor de Entropía y Seguridad de Contraseñas")
    p.add_argument("-p", "--password", type=str, help="Contraseña a auditar")
    p.add_argument("-g", "--generate", action="store_true", help="Generar contraseña segura")
    p.add_argument("-l", "--length", type=int, default=16, help="Longitud de contraseña generada")
    p.add_argument("-d", "--dict", type=str, help="Ruta a diccionario de contraseñas")
    args = p.parse_args()
    
    auditor = PasswordAuditor(args.dict)
    if args.generate:
        pwd = auditor.generate_secure_password(args.length)
        print(f"[+] Contraseña generada: {pwd}")
        return display_report(auditor.audit(pwd))
    if args.password: return display_report(auditor.audit(args.password))

    while True:
        print(f"\n{'='*50}\n 1. Evaluar contraseña (Oculta)\n 2. Evaluar contraseña (Visible)\n 3. Generar contraseña aleatoria\n 0. Salir\n{'='*50}")
        opc = input("Opción: ").strip()
        if opc in ("1", "2"):
            pwd = getpass.getpass("Contraseña: ") if opc == "1" else input("Contraseña: ")
            if pwd: display_report(auditor.audit(pwd))
        elif opc == "3":
            l = input("Longitud [16]: ").strip()
            pwd = auditor.generate_secure_password(int(l) if l.isdigit() else 16)
            print(f"\n[+] Generada: {pwd}")
            display_report(auditor.audit(pwd))
        elif opc == "0": break

if __name__ == "__main__":
    main()