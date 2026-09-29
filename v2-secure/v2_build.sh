#!/usr/bin/env bash
# build.sh -- baut das GEHÄRTETE Challenge-Binary (v2)
set -e

echo "[*] Kompiliere lv (gehärtet, optimiert)..."
# -O2 verschleift den Kontrollfluss zusätzlich; -s strippt Symbole;
# -fno-asynchronous-unwind-tables macht das Binary schlanker/undurchsichtiger.
gcc -O2 -s -fno-asynchronous-unwind-tables -o lv v2_lv.c

echo "[*] Zusätzliches Strippen (Sicherheitsnetz)..."
strip --strip-all lv 2>/dev/null || true

echo "[*] Kompiliere Referenz-Cipher (Invertierbarkeits-Beweis)..."
gcc -O2 -o reference_cipher v2_reference_cipher.c

echo "[*] Kompiliere Musterlösung..."
gcc -O2 -o solve v2_solve.c

echo ""
echo "[+] Fertig."
echo "    ./lv hello                 -> Access denied."
echo "    ./lv s3cr3t_l1c3ns3_k3y    -> Access granted."
echo "    ./solve                    -> RECOVERED FLAG: FLAG{...}"
echo ""
echo "[!] WICHTIG: In Ghidra öffnen und prüfen, wie reveal()/f0()/init_state()"
echo "    tatsächlich dekompiliert werden. Dort die Reibung empirisch messen."
