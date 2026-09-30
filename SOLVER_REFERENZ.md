# Solver-Referenz — License Validator (v2, gehärtet)

> **Zweck dieses Dokuments.** Dies ist eine *technische Referenz* des vorgesehenen
> Lösungswegs — als Lern- und Verifikationsgrundlage. Die einzureichende
> 5-Punkte-RE-Doku formulierst du daraus **in eigenen Worten**, nachdem du jeden
> Schritt selbst nachvollzogen hast. Stellen, die mit **[SELBST PRÜFEN]** markiert
> sind, hängen vom echten Ghidra-/objdump-Output deines x86-64-ELF ab und müssen
> von dir empirisch bestätigt werden.

---

## 0. Überblick: Worum geht es?

Die Anwendung `lv` ist ein „Lizenz-Validator". Sie nimmt ein Passwort als
Argument und antwortet mit `Access denied.` oder `Access granted.`. Versteckt im
Binary liegt eine verschlüsselte Flag `FLAG{...}`, die **unabhängig vom Passwort**
entschlüsselt werden kann.

Das Sicherheitsproblem in einem Satz: **Das Schutzverfahren ist symmetrisch und
vollständig invertierbar, und sämtliches Schlüsselmaterial liegt im Binary — es
handelt sich um reine Security-through-Obscurity ohne echte kryptografische
Einwegfunktion.**

Der Angriff besteht darin, die verschlüsselte Flag aus `.rodata` zu extrahieren
und die fünf Transformationsrunden rückwärts anzuwenden. Alle dafür nötigen
Konstanten stehen sichtbar im Binary.

---

## 1. Benötigte Tools

| Tool | Zweck |
|------|-------|
| `file` | Verifizieren, dass es ein x86-64-ELF ist |
| `strings` | Erste Orientierung: sichtbare Textfragmente |
| `objdump -s -j .rodata` | Eingebettete Daten (Ciphertext + Tabellen) auslesen |
| `objdump -d` | Disassembly der Funktionen |
| Ghidra | Dekompilierung nach Pseudo-C (für die Rundenlogik) |
| Ein C-Compiler *oder* Python | Den Solver nachbauen und laufen lassen |

---

## 2. Schritt-für-Schritt-Angriff

### Schritt 1 — Orientierung (Blackbox)
Programm ein paarmal ausführen, Verhalten beobachten:
```
./lv test            -> Access denied.
./lv ""              -> Access denied.
```
Erkenntnis: Ein Passwort-Gate. Kein sichtbares Flag im Output — also muss es
intern verschlüsselt vorliegen.

### Schritt 2 — Statische Inspektion
```
file lv
strings lv
```
`strings` zeigt die sichtbaren Meldungen („Access denied." etc.), aber **keine
Flag** — sie ist verschlüsselt, nicht als Klartext vorhanden. Das ist der Hinweis,
dass sie in den Datenbereichen verschleiert liegt.

### Schritt 3 — Eingebettete Daten extrahieren
```
objdump -s -j .rodata lv
```
**[SELBST PRÜFEN]** Hier findest du die Byte-Blöcke. Zu identifizieren sind:
- **19 Bytes Ciphertext** (im Code `A1[]`): die verschlüsselte Flag.
- **16 Bytes Tabelle** (im Code `A0[]`): wird zum Runden-Seed gefaltet.
- **4×32-Bit-Werte** (im Code `P0[]`): werden zu zwei „Konstanten" rekombiniert.

Der erwartete Ciphertext (zur Selbstkontrolle):
`84 C3 37 2E 43 88 10 41 76 B4 14 E6 62 16 C4 A4 39 32 F3`

### Schritt 4 — Rundenlogik aus Ghidra lesen
**[SELBST PRÜFEN]** In Ghidra ist die zentrale Funktion (im Quelltext `reveal()`,
gestrippt heißt sie `FUN_...`) zu finden. Sie enthält fünf verschränkte Phasen.
Ghidra rendert einige Operationen ungenau — insbesondere:
- die Rotationen `(v<<r)|(v>>(8-r))` erscheinen oft als verschachtelte Shifts,
- die 8-Bit-Overflow-Faltung `acc*33+c` erscheint als `int`-Arithmetik ohne
  sichtbare `& 0xFF`-Reduktion.
Diese Stellen musst du beim Nachbauen korrekt als 8-Bit-Operationen interpretieren.

### Schritt 5 — Die Kette rückwärts anwenden
Die Entschlüsselung wendet die fünf Runden in umgekehrter Reihenfolge an. Details
je Runde in Abschnitt 3. Ergebnis: `FLAG{4cc3ss_d3n13d}`.

---

## 3. Die fünf Runden im Detail

> Reihenfolge der **Ver**schlüsselung (Build-Zeit): R1 → R2 → R3 → R4 → R5.
> **Ent**schlüsselung (Angriff): R5⁻¹ → R4⁻¹ → R3⁻¹ → R2⁻¹ → R1⁻¹.

### R1 — Additive Verkettung + datenabhängige Rotation
- **Vorwärts:** `x = rotl(x + seed ^ prev, prev&7)`, wobei `seed` aus `A0[]`
  gefaltet wird und `prev` das jeweils vorige *Ausgabe*-Byte ist.
- **Umkehr-Kernidee:** `prev` ist das Ciphertext-Byte (bekannt), also rückwärts
  auflösbar: erst rechts-rotieren, dann `^prev`, dann `-seed`.
- **Reibung:** Der Seed steht nirgends als Zahl — man muss die Faltung
  nachrechnen. Die datenabhängige Rotation erzwingt korrekte Reihenfolge.

### R2 — S-Box-Substitution mit datenabhängigem Index
- **Vorwärts:** `y = SBOX[(x + prev) & 0xFF]`, `prev = y`.
- **Umkehr:** Inverse S-Box bilden, `x = INV[y] - prev`.
- **Reibung:** Die S-Box ist ein 256-Byte-Block in `.rodata`, den man extrahieren
  (oder aus dem Bildungs-Code nachbauen) muss.

### R3 — Overflow-Fold-Akkumulator
- **Vorwärts:** `c = p ^ acc; acc = (acc*33 + c) & 0xFF`.
- **Umkehr:** `p = c ^ acc; acc = (acc*33 + c) & 0xFF` (acc schreitet auf dem
  *bekannten* Ciphertext-Byte fort → eindeutig umkehrbar).
- **Reibung:** Die implizite 8-Bit-Reduktion (`*33` in `uint8_t`) ist die Stelle,
  die Ghidra als 32-Bit-`int` zeigt und die man leicht falsch nachbaut.

### R4 — Positionsabhängige Addition aus rotierendem Kontext
- **Vorwärts:** `b[i] += (ctx >> ...) & 0xFF`, `ctx` rotiert je Schritt.
- **Umkehr:** dieselbe Rotation, aber Subtraktion.
- **Reibung [SELBST PRÜFEN]:** `ctx` wird in `init_state()` aus `P0[]`
  rekombiniert (`P0[0]|P0[1]` = `0xC0DE1337`). Der Wert steht nicht direkt da —
  verteilter Zustand über zwei Funktionen.

### R5 — LCG-Keystream-XOR  ← **DIE BENANNTE SCHWÄCHE**
- **Vorwärts:** LCG `state = state*1103515245 + 12345` (glibc-Parameter), das
  High-Byte jedes Zustands bildet den Keystream, der mit den Daten ge-XOR-t wird.
- **Seed:** eine **feste, im Binary sichtbare Konstante** (`0x1337C0DE`), *nicht*
  vom Passwort oder von den Daten abhängig.
- **Umkehr:** identisch zur Vorwärtsrichtung (XOR ist selbstinvers), da der
  Keystream vollständig aus der sichtbaren Konstante reproduzierbar ist.

---

## 4. Die Sicherheitsschwäche — für die Erklärung

Der springende Punkt, den der Dozent hören will:

1. **Kein echter Schlüssel.** Der LCG-Seed und alle Rundenkonstanten sind fest im
   Binary. Es gibt kein Geheimnis, das *nicht* im Programm steht.
2. **Vollständig invertierbar.** Jede Runde ist eine Bijektion; die gesamte Kette
   lässt sich Byte für Byte rückwärts rechnen.
3. **Passwort-Gate ist Dekoration.** Der Passwort-Check (ein Hash-Vergleich) ist
   vom Flag völlig entkoppelt — die Flag hängt nicht am Passwort. Der „Schutz" ist
   also umgehbar, ohne das Passwort je zu kennen.
4. **Security through Obscurity.** Die einzige „Sicherheit" ist die Mühe, den Code
   zu verstehen. Sobald er verstanden ist, gibt es keinerlei kryptografische
   Barriere. Ein LCG ist kein sicherer Keystream-Generator — er ist linear und
   vorhersagbar.

**Kernsatz:** *„Die Flag ist symmetrisch mit im Binary hinterlegten Konstanten
verschlüsselt und daher vollständig invertierbar; der Passwortschutz ist davon
entkoppelt und somit irrelevant für den Zugriff auf die Flag."*

---

## 5. Der Solver

Ein lauffähiger Referenz-Solver liegt als `v2_solve.c` bei. Er nutzt **nur** die
aus dem Binary lesbaren Daten (Ciphertext + Konstanten) und die fünf inversen
Runden, und gibt die Flag aus — ohne das Passwort und ohne das Zielprogramm
auszuführen. Das ist der Beweis, dass der Schutz keinen realen Widerstand bietet.

**[SELBST PRÜFEN]** Baue den Solver selbst nach (in C oder Python), indem du die
fünf Runden aus dem Ghidra-Output rekonstruierst. Wenn dein selbstgebauter Solver
`FLAG{4cc3ss_d3n13d}` ausgibt, hast du den Weg vollständig verstanden — und *das*
ist die Grundlage, aus der du die Doku in eigenen Worten schreibst.
