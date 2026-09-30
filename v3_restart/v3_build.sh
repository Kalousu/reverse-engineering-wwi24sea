#!/usr/bin/env bash
set -e
echo "[*] Kompiliere lockbox (Challenge-Binary)..."
gcc -O2 -s -fno-asynchronous-unwind-tables -o lockbox v3_lockbox.c
strip --strip-all lockbox 2>/dev/null || true

echo "[*] Kompiliere Referenz-Solver..."
gcc -O2 -o solve v3_solve.c

echo ""
echo "[+] Fertig."
echo "    Falsches Passwort: ./lockbox d v3_key 'falsch' v3_secret.txt.enc out.txt   -> Muell"
echo "    Solver (kein PW):  ./solve v3_key v3_secret.txt.enc                        -> RECOVERED: FLAG{...}"
