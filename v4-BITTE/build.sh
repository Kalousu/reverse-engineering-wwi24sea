#!/usr/bin/env bash
#
# build.sh -- baut LicenseGuard v4 nach ../build
#
# Zwei Modi:
#   ./build.sh              (auto: baut fuer die aktuelle Plattform)
#   ./build.sh --linux      (erzwingt Linux x86-64 ELF  = die ABGABE)
#   ./build.sh --macos      (erzwingt macOS-Build         = nur LOKALER Test)
#
#   STRIP=0 ./build.sh      (Symbole drinlassen; Default: strippen)
#
# WICHTIG:
#   * Die ABGABE zum Reverse-Engineering ist IMMER das x86-64 Linux ELF,
#     gebaut in der Lima/Linux-VM (--linux bzw. auto unter Linux).
#   * Der macOS-Build ist ein Mach-O/ARM64-Binary und dient NUR dem
#     funktionalen Testen der Pruef-Logik auf dem Host -- er entspricht
#     NICHT dem Abgabe-Artefakt und ist fuer die RE-Aufgabe irrelevant.
#
set -euo pipefail

CC="${CC:-cc}"
CFLAGS="${CFLAGS:--O2}"
OUTDIR="../build"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# --- Ziel bestimmen ----------------------------------------------------
TARGET="auto"
case "${1:-}" in
    --linux) TARGET="linux" ;;
    --macos) TARGET="macos" ;;
    "")      TARGET="auto" ;;
    *) echo "usage: $0 [--linux|--macos]" >&2; exit 1 ;;
esac

HOST_OS="$(uname -s)"
HOST_ARCH="$(uname -m)"

if [ "$TARGET" = "auto" ]; then
    case "$HOST_OS" in
        Linux)  TARGET="linux" ;;
        Darwin) TARGET="macos" ;;
        *) echo "FEHLER: unbekannte Plattform $HOST_OS" >&2; exit 1 ;;
    esac
fi

[ -f lv.c ] || { echo "FEHLER: lv.c nicht gefunden." >&2; exit 1; }
mkdir -p "$OUTDIR"

# --- Linux-Build (DIE ABGABE) -----------------------------------------
if [ "$TARGET" = "linux" ]; then
    if [ "$HOST_OS" != "Linux" ]; then
        echo "FEHLER: --linux muss in der Linux-VM (Lima) laufen." >&2
        echo "        Host ist $HOST_OS. Cross-Compile ist hier nicht eingerichtet." >&2
        exit 1
    fi
    if [ "$HOST_ARCH" != "x86_64" ]; then
        echo "WARNUNG: Host-Arch $HOST_ARCH != x86_64 -- Binary passt evtl." \
             "nicht zur Aufgabe (x86-64 ELF erwartet)." >&2
    fi
    OUT="$OUTDIR/lv"
    echo "[linux] kompilieren -> $OUT ..."
    "$CC" $CFLAGS -o "$OUT" lv.c

# --- macOS-Build (NUR LOKALER FUNKTIONSTEST) --------------------------
elif [ "$TARGET" = "macos" ]; then
    if [ "$HOST_OS" != "Darwin" ]; then
        echo "FEHLER: --macos muss auf macOS laufen (Host ist $HOST_OS)." >&2
        exit 1
    fi
    OUT="$OUTDIR/lv_macos_test"   # bewusst anderer Name -> keine Verwechslung mit Abgabe
    echo "[macos] kompilieren -> $OUT  (NUR lokaler Test, NICHT die Abgabe) ..."
    "$CC" $CFLAGS -o "$OUT" lv.c
fi

# --- optional strippen -------------------------------------------------
if [ "${STRIP:-1}" != "0" ]; then
    strip "$OUT" 2>/dev/null && echo "       gestrippt." || echo "       (strip uebersprungen)"
fi

# --- pruefen + testen --------------------------------------------------
command -v file >/dev/null 2>&1 && file "$OUT"

set +e
OK="$("$OUT" 'FLAG{4cc3ss_d3n13d}')"; R1=$?
BAD="$("$OUT" 'AAAAAAAAAAAAAAAAAAA')"; R2=$?
set -e
echo "  richtiger Key: \"$OK\" (exit $R1)"
echo "  falscher Key : \"$BAD\" (exit $R2)"
echo "$OK"  | grep -q granted || { echo "FEHLER: Key abgelehnt." >&2; exit 1; }
echo "$BAD" | grep -q denied  || { echo "FEHLER: falscher Key akzeptiert." >&2; exit 1; }
strings "$OUT" | grep -qF 'FLAG{' && echo "  WARN: Key leakt!" || echo "  leak-check: ok"

echo
if [ "$TARGET" = "linux" ]; then
    echo "FERTIG. ABGABE-Binary: $OUT  (x86-64 ELF -- dieses weitergeben)"
else
    echo "FERTIG. Test-Binary: $OUT  (nur lokaler Funktionstest -- NICHT abgeben!)"
    echo "        Fuer die Abgabe in der Lima-VM bauen:  ./build.sh --linux"
fi
