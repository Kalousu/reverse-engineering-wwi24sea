#!/usr/bin/env bash
#
# build.sh -- baut LicenseGuard (v3) aus lv.c + genhash.c in einem Schritt.
#
# Ablauf:
#   1. genhash kompilieren
#   2. Soll-Hash fuer den gewuenschten Key erzeugen
#   3. STORED_HASH[] in lv.c automatisch ersetzen
#   4. lv kompilieren
#   5. Funktionstest (richtiger Key -> granted, falscher -> denied)
#
# Aufruf:
#   ./build.sh 'DEIN-LIZENZSCHLUESSEL'
#
# Der Key steht NIRGENDS im erzeugten Binary -- nur sein Hash. Das
# fertige ./lv ist das einzige Artefakt, das man zum Reverse-Engineering
# abgibt. genhash/lv.c NICHT mitgeben (sonst Offline-Brute-Force moeglich).

set -euo pipefail

# --- Argument pruefen -------------------------------------------------
if [ "$#" -ne 1 ]; then
    echo "usage: $0 '<license-key>'" >&2
    exit 1
fi
KEY="$1"

CC="${CC:-gcc}"
CFLAGS="${CFLAGS:--O2}"

# --- Vorbedingungen ---------------------------------------------------
for f in lv.c genhash.c; do
    if [ ! -f "$f" ]; then
        echo "FEHLER: $f nicht gefunden (im selben Verzeichnis ausfuehren)." >&2
        exit 1
    fi
done

echo "[1/5] genhash kompilieren ..."
"$CC" $CFLAGS -o genhash genhash.c

echo "[2/5] Soll-Hash fuer den Key erzeugen ..."
# genhash gibt den kompletten 'static const uint8_t STORED_HASH[32] = {...};'
# Block aus. Wir schneiden genau diesen Block heraus.
HASH_BLOCK="$(./genhash "$KEY" | sed -n '/static const uint8_t STORED_HASH/,/};/p')"

if [ -z "$HASH_BLOCK" ]; then
    echo "FEHLER: genhash lieferte keinen STORED_HASH-Block." >&2
    exit 1
fi

echo "[3/5] STORED_HASH[] in lv.c einsetzen ..."
# Sicherungskopie der Quelle (wir editieren eine Arbeitskopie, nicht das
# Original -- so bleibt lv.c als Platzhalter-Vorlage erhalten).
cp lv.c lv.gen.c

# Den vorhandenen STORED_HASH-Block in der Arbeitskopie durch den neuen
# ersetzen. Wir nutzen ein kleines Python-Snippet, weil multiline-Regex
# in sed/awk fehleranfaellig ist.
HASH_BLOCK="$HASH_BLOCK" python3 - << 'PY'
import os, re
block = os.environ["HASH_BLOCK"].strip()
src = open("lv.gen.c").read()
new = re.sub(
    r'static const uint8_t STORED_HASH\[32\]\s*=\s*\{.*?\};',
    block,
    src, count=1, flags=re.S)
if new == src:
    raise SystemExit("FEHLER: STORED_HASH-Block in lv.c nicht gefunden.")
open("lv.gen.c", "w").write(new)
print("      -> Hash eingesetzt (lv.gen.c)")
PY

echo "[4/5] lv kompilieren ..."
"$CC" $CFLAGS -o lv lv.gen.c

echo "[5/5] Funktionstest ..."
set +e
OUT_OK="$(./lv "$KEY")"
RC_OK=$?
OUT_BAD="$(./lv "${KEY}_falsch")"
RC_BAD=$?
set -e

echo "      richtiger Key : \"$OUT_OK\" (exit $RC_OK)"
echo "      falscher Key  : \"$OUT_BAD\" (exit $RC_BAD)"

# Erwartung pruefen
if [ "$RC_OK" -ne 0 ] || ! printf '%s' "$OUT_OK" | grep -q "granted"; then
    echo "FEHLER: richtiger Key wurde NICHT akzeptiert." >&2
    exit 1
fi
if [ "$RC_BAD" -eq 0 ] || ! printf '%s' "$OUT_BAD" | grep -q "denied"; then
    echo "FEHLER: falscher Key wurde faelschlich akzeptiert." >&2
    exit 1
fi

# Leak-Check: der Klartext-Key darf nicht im Binary stehen
if strings lv | grep -qF "$KEY"; then
    echo "WARNUNG: Klartext-Key taucht im Binary auf! (sollte nicht sein)" >&2
else
    echo "      leak-check     : Key nicht im Binary (ok)"
fi

echo
echo "FERTIG. Abgabe-Binary: ./lv"
echo "        (NUR ./lv abgeben -- nicht lv.c / lv.gen.c / genhash / build.sh)"
