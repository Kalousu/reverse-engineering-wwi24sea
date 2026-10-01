#!/usr/bin/env bash
# build.sh -- baut das v5-combined Challenge-Binary
set -e

mkdir -p ../build

echo "[*] Kompiliere v5_lv..."
if [[ "$(uname)" == "Linux" ]]; then
    gcc -O2 -s -fno-asynchronous-unwind-tables -o ../build/lv_v5 v5_lv.c
    strip --strip-all ../build/lv_v5 2>/dev/null || true
    echo "[*] Linux ELF gebaut: ../build/lv_v5"
else
    gcc -O2 -o ../build/lv_v5_test v5_lv.c
    echo "[*] macOS Test-Binary gebaut: ../build/lv_v5_test (nicht die Abgabe!)"
fi

echo ""
echo "[+] Fertig."
echo "    ./lv_v5 hello                  -> Access denied."
echo "    ./lv_v5 'FLAG{4cc3ss_d3n13d}'  -> Access granted."
echo ""
echo "[!] Zum Berechnen eines neuen A1[]: python3 calc_a1_v5.py"
