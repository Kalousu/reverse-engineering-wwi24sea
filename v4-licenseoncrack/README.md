# LicenseGuard v3 -- konzeptionelle Haertung

## Problem der Vorgaenger (v1 / v2)
v1 und v2 (letztere obfuskiert mit CFF, MBA, VM, opaque predicates ...)
**rekonstruieren den gueltigen Schluessel zur Laufzeit im RAM** und
vergleichen ihn dann byteweise:

    uint8_t key[19];
    reveal(key, 19);                 // key[] = Klartext-Schluessel
    ok = eq_ct(eingabe, key, 19);    // byteweiser Vergleich

Dadurch MUSS der Klartext im Speicher stehen. Angriff:

    (gdb) break *<reveal>
    (gdb) finish
    (gdb) x/s $buf      ->  FLAG{4cc3ss_d3n13d}

Obfuskierung verhindert das NICHT -- sie verschleiert nur den Weg zur
Rekonstruktion, nicht die Rekonstruktion selbst.

## Fix in v3 -- Richtung umdrehen
- KEIN gespeicherter Klartext-Schluessel mehr.
- Eingabe wird **gehasht** (Einwegfunktion) und der Hash gegen einen
  fest eingebauten Soll-Hash geprueft.
- Hash ist nicht umkehrbar -> aus RAM-Inhalt (Soll-Hash + Hash der
  Eingabe) laesst sich der gueltige Schluessel nicht zurueckrechnen.
- Hash iteriert (3 Mio Runden, ~0.45 s/Versuch) + Salt -> Brute-Force
  verteuert, keine Rainbow-Tables.

## Nachweis
- `strings lv | grep FLAG` -> kein Treffer (kein Key im Binary).
- RAM-Scan waehrend der Ausfuehrung (ramscan2.py): der einzige
  Klartext-Key im Speicher ist argv[1], das der Angreifer SELBST
  uebergeben hat. Es gibt keinen vom Programm erzeugten Klartext-Puffer.

## Verbleibende Grenzen (ehrlich)
1. Der "ok"-Branch ist weiter patchbar (je->jmp) -> "granted" ohne Key.
   Hash-Verify verhindert das AUSLESEN, nicht das UMGEHEN.
   Vollstaendige Abwehr: Schluessel eine echte Decrypt-Key ableiten
   lassen (AEAD), sodass ohne Key keine Funktionalitaet existiert.
2. Selbstgebauter Hash nur fuer die Uebung. Produktion: Argon2id/
   scrypt/bcrypt mit zufaelligem Salt pro Lizenz.
3. Brute-Force bleibt moeglich bei zu kleinem Schluesselraum ->
   ausreichende Entropie noetig.

## Build
    gcc -O2 -o genhash genhash.c
    ./genhash 'DEIN-KEY'              # Ausgabe -> STORED_HASH in lv.c
    gcc -O2 -o lv lv.c
    ./lv 'DEIN-KEY'                   # Access granted.
