#!/usr/bin/env bash
# build.sh -- baut LicenseGuard v4 (fies, aber loesbar).
# Der Key ist ueber A1[] fest eingebacken; ein Key-Wechsel erfordert
# Neuberechnung von A1[] (calc_a1.py). Fuer die Standard-Flag genuegt:
#   ./build.sh
set -euo pipefail
CC="${CC:-gcc}"; CFLAGS="${CFLAGS:--O2}"
[ -f lv.c ] || { echo "lv.c fehlt" >&2; exit 1; }
echo "[1/2] lv kompilieren ..."
"$CC" $CFLAGS -o lv lv.c
echo "[2/2] Funktionstest ..."
set +e
OK="$(./lv 'FLAG{4cc3ss_d3n13d}')"; R1=$?
BAD="$(./lv 'AAAAAAAAAAAAAAAAAAA')"; R2=$?
set -e
echo "  richtig: \"$OK\" (exit $R1)"
echo "  falsch : \"$BAD\" (exit $R2)"
[ $R1 -eq 0 ] && echo "$OK" | grep -q granted || { echo "FEHLER: Key abgelehnt"; exit 1; }
[ $R2 -ne 0 ] && echo "$BAD" | grep -q denied || { echo "FEHLER: falscher Key akzeptiert"; exit 1; }
strings lv | grep -qF 'FLAG{' && echo "WARN: Key leakt im Binary!" || echo "  leak-check: ok"
echo "FERTIG. Abgabe: NUR ./lv"
