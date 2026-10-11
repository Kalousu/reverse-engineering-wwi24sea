# 5-Punkte Abgabe

## Wo genau liegt das Sicherheitsproblem in diesem Programm?

Nach eigener Recherche von Obfuskations- bzw. Verschleierungstechniken wie z.B. Konstanten-Splitting und Anti-Debug hat unsere Gruppe (Jonas und Ich, Kevin) sich entschieden, eine Art Lizensvalidator zu schreiben, welche ein Passwort entgegennimmt. Dieses Passwort liegt nicht im Klartext vor, sondern es wird aus programminternen Konstanten berechnet. Dafür muss man diese programminterne Konstanten finden, welche hinter sehr vielen Verschleierungstechniken versteckt sind. Der finale Abgleich des Passworts mit der Eingabe erfolgt über einen Hash (FNV-1a) statt eines direkten Byte-Vergleichs, sodass der erwartete Text zu keiner Zeit im Klartext im Speicher vorhanden ist. Wir haben darauf geachtet keine künstlichen Schwierigkeiten wie z.b. Brute-Forcing miteinzubauen, damit das Gefühl einer CTF Aufgabe einigermaßen erhalten bleibt und die Aufgabe auch wenigstens etwas Spaß macht.

### Der eigentliche Konstruktionsfehler
 
Die Verifikation in `main()` lautet im Kern:
 
```c
uint32_t h_got  = 2166136261u;   /* FNV-1a offset basis */
uint32_t h_want = 2166136261u;
for (int i = 0; i < KEYLEN; i++) {
    uint8_t t   = target_byte(rbuf[i], i, seedb, prev, ad_skew, t_skew); /* Sollwert */
    uint8_t inb = in[i];                                                 /* Eingabe  */
    h_got  = (h_got  ^ inb) * 16777619u;
    h_want = (h_want ^ t)   * 16777619u;
    prev = t;
}
int ok = len_ok && (h_got == h_want);
```
 
**Der Sollwert `t` wird vollständig unabhängig von der Eingabe berechnet.** Die Eingabe fließt ausschließlich in `h_got`; `h_want` entsteht nur aus programminternen Daten (`A1[]`, den gesplitteten `CS_*`-Konstanten, `A0[]`). Es gibt kein Geheimnis außerhalb des Binaries — kein Server, kein Salt, keine Hardware-Bindung. Wer die Sollwerte `t[0..18]` nachrechnet, **kennt den Schlüssel byteweise**; der FNV-Hash verhindert nur das direkte *Auslesen* der Sollwerte im Speicher, nicht das *Nachrechnen*. Die Transformation ist byteweise bijektiv, daher ist kein Brute-Forcing nötig — man invertiert bzw. rechnet schlicht nach.

## Verwendete Tools, um die Sicherheitslücke auszunutzen:

Verwendete Tools (jeweils mit Version und Installationsbefehl in der Doku):
- gcc: Binary bauen und Keygen kompilieren
- python3: eigenständiges Keygen und Binary-Patcher
- binutils (objdump, nm): Disassembly und Symbol-/Offset-Ermittlung
- Ghidra: Statische Analyse des Codes, interpretierte Codeabschnitte

**Beiliegende Skripte (vollständig und lauffähig):**
- solve.py: reimplementiert die Logik ohne Quellcode.
- keygen.c: nutzt die Original-Routinen aus `v5_lv.c` als unabhängige Gegenprobe.
- patch.py: setzt `debugger_skew()`/`timing_skew()` auf „return 0" (x86_64).
- calc_a1_v5.py: **Autoren-Werkzeug**: berechnet aus dem gewählten Key das `A1[]`, das ins Binary gebacken wird (zeigt, *wie die Challenge gebaut wurde* — nicht der Angriffsweg).

## Wie sind wir dabei vorgegangen?

In der Vorgehensweise.md steht eine Zusammenfassung unserer KI bei der Vorgehensweise (Claude Opus 4.8). In ./Tools sind die Tools beigelegt.

