# v4 -- Write-up (Loesungsweg, belegt die Knackbarkeit)

## Was v4 gegenueber v1/v2 aendert
v1/v2 rekonstruierten den **ganzen** Key in **einen** Puffer und
verglichen danach -> ein einziger `break reveal; x/s $buf` genuegte.

v4 nimmt dem genau diese Grundlage:

1. **[NODUMP] Zeichenweise Pruefung mit sofortigem Wipe.** Pro Position
   wird nur EIN Soll-Byte gebildet, verglichen und sofort ueber-
   schrieben. Der vollstaendige Key steht nie zusammenhaengend im RAM.
   -> Der naive Dump liefert Muell.

2. **[INPUT] Eingabe-/positionsabhaengige Pruefung.** Kein gespeicherter
   Soll-Key-Puffer; der Zielwert je Byte entsteht aus A1[i], einem Seed
   und der Verkettung mit dem Vorgaenger.

3. **[AD] Anti-Debugging.** `ptrace(TRACEME)` erkennt einen angehaengten
   Debugger und speist einen Versatz (skew=0x6B) in die Zielwert-
   Berechnung ein -> unter gdb/strace schlaegt selbst der RICHTIGE Key
   fehl. Der Analyst muss das zuerst bemerken und umgehen.

4. **[MBA]/[OP]/[CSPLIT]** wie v2 als zusaetzliche Lese-Huerde.

## Warum es trotzdem loesbar ist (die Intention)
Die Pro-Byte-Transformation ist **invertierbar** und haengt nur von
statisch extrahierbaren Werten ab:

    target(i) = ((((A1[i] ^ seedb(i)) + 7*i) ^ prev) + skew)
    prev_0 = 0x2A (IV),  prev_{i} = target(i-1)
    seedb(i) = (seed >> (8*(i mod 4))) & 0xFF,  seed = 0x5AA53CC3
    skew = 0  (sobald Anti-Debug umgangen/als 0 erkannt)

Da `target(i)` gleich dem gesuchten Key-Byte ist und alle Eingaenge
bekannt sind, rechnet man den Key Position fuer Position aus.

## Konkreter Loesungsweg
1. **Statik (Ghidra):** `main` finden, die Pruefschleife lesen. A1[] als
   19-Byte-Array in .rodata ablesen. Seed aus CS_SEED (0x5AA53CC3) und
   den IV (0x2A) im Code ablesen.
2. **Anti-Debug erkennen:** den `ptrace`-Aufruf und den 0x6B-Versatz
   identifizieren. Fuer die statische Loesung ignoriert man den
   Debugger-Pfad einfach (skew=0). Fuer die dynamische Loesung patcht
   man den ptrace-Zweig oder setzt den Rueckgabewert in gdb auf 0.
3. **Invertieren:** target(i) mit den bekannten Werten aufloesen
   (siehe solve.py). Ergebnis:

       FLAG{4cc3ss_d3n13d}

4. **Verifizieren:** `./lv 'FLAG{4cc3ss_d3n13d}'` -> Access granted.

## Alternativer dynamischer Weg
Watchpoint auf das jeweilige Eingabe-Byte bzw. Breakpoint auf den
Vergleich (`diff == 0`). Da pro Iteration genau ein Soll-Byte `t`
kurz existiert, liest man es Iteration fuer Iteration aus `t` aus --
19 Einzelwerte statt eines Dumps. Anti-Debug vorher neutralisieren.

## Dateien
- lv.c        : Quellcode v4
- calc_a1.py  : erzeugt A1[] fuer einen beliebigen Key (Builder-Seite)
- solve.py    : rechnet den Key zurueck (Loeser-Seite, Beweis)
- build.sh    : baut + testet ./lv
- Abgabe zum Knacken: NUR ./lv

## Bauen
In der Lima/Linux-VM (das ist die ABGABE):
    ./build.sh --linux      # oder einfach ./build.sh (auto)
    -> ../build/lv  (x86-64 ELF, stripped)

Nur zum lokalen Funktionstest auf dem Mac (NICHT die Abgabe):
    ./build.sh --macos
    -> ../build/lv_macos_test  (Mach-O/ARM64, anderer Name, nicht abgeben)

Hinweis: Ein macOS/ARM-Build testet nur, OB die Pruef-Logik Keys
richtig akzeptiert/ablehnt. Das reverse-engineerte Artefakt ist immer
das x86-64 Linux ELF. Zum Knacken wird NUR ../build/lv weitergegeben.
