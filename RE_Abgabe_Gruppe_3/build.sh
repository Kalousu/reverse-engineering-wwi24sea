#!/usr/bin/env bash
# build.sh -- baut das v5-combined Challenge-Binary
set -e

mkdir -p ../build

echo "[*] Kompiliere v5_lv..."
if [[ "$(uname)" == "Linux" ]]; then
    gcc -O2 -s -fno-asynchronous-unwind-tables -o ./License_Validator_x86_64 v5_lv.c
    strip --strip-all ./License_Validator_x86_64 2>/dev/null || true
    echo "[*] Linux ELF gebaut: ./License_Validator_x86_64"
else
    gcc -O2 -o ./License_Validator_ARM v5_lv.c
    echo "[*] macOS Test-Binary gebaut: ./License_Validator_ARM (nicht die Abgabe)"
fi

echo ""
echo "[+] Fertig."
echo "    ./License_Validator hello                  -> Access denied."
echo "    ./License_Validator 'FLAG{4cc3ss_d3n13d}'  -> Access granted."
echo ""
echo "[!] Zum Berechnen eines neuen A1[]: python3 calc_a1_v5.py"
