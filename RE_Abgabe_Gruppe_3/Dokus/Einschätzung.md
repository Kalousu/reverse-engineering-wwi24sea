# 2-Punkte Abgabe — Einschätzung: Wie gut hält unser Schutz eine KI vom Reversen ab?
 
## Kurzfazit
 
| Angreifer | Resistenz unseres Schutzes |
|---|---|
| KI mit Code-Execution-Harness **+ Quellcode** | **sehr gering** — Key in Minuten |
| KI mit Harness, **nur Binary** (nicht gestrippt) | **gering** |
| KI ohne Werkzeuge (reiner Chat, Code eingefügt) | **gering–mittel** |
| KI gegen ein *gut* geschütztes Ziel (Vergleich) | hoch — aber das sind wir nicht |
 
Unser Mechanismus erhöht für eine KI vor allem den **Zeit-/Token-Aufwand**, bietet aber keine prinzipielle Hürde. Der Grund ist derselbe wie beim menschlichen Angreifer: Das Geheimnis liegt vollständig lokal im Binary, und sämtliche Verschleierung ist **deterministisch und mustererkennbar** — genau die Art von Arbeit, die eine KI mit Ausführungsumgebung sehr gut automatisiert.
 
## Empirischer Beleg
 
In einem praktischen Test genügte ein **Standard-Harness** (Shell, `gcc`, `python3`, binutils), um den Schutz vollständig zu brechen: die Transformationspipeline (`reveal` + `target_byte`) wurde reimplementiert und der Key `FLAG{4cc3ss_d3n13d}` in wenigen Minuten rekonstruiert und gegen das unveränderte Binary verifiziert. Es war **kein Brute-Force, keine dynamische Analyse und kein Umgehen des Anti-Debuggings** nötig — rein statisches Nachrechnen reichte.
 
## Warum die einzelnen Schutzschichten eine KI kaum bremsen
 
- **MBA** sind algebraische Identitäten (`(a|b)-(a&b) == a^b`). Eine KI erkennt das Muster oder verifiziert es per erschöpfendem Test über 256×256 Paare. Dafür existieren sogar dedizierte Simplifier (SSPAM, GAMBA) und SMT-Solver (z3).
- **Control-Flow-Flattening** ist ein Zustandsautomat mit fester Transitionsfolge → linearisierbar; Werkzeuge wie angr/miasm automatisieren das.
- **Die Mini-VM** hat 5 feste Opcodes und ein statisches Programm → trivial devirtualisierbar.
- **Opaque Predicates** sind konstant und werden durch Nachrechnen/SMT sofort entlarvt.
- **Konstanten-Splitting** ist nur ein Big-Endian-Zusammensetzen.
- **Anti-Debug (ptrace/Timing)** ist für die **statische** Analyse schlicht irrelevant — und selbst dynamisch leicht zu patchen.
Entscheidend: Keine dieser Schichten verlagert das Geheimnis aus dem Binary oder erzwingt Brute-Force. Sie kosten nur Analysezeit.
 
## Welche Tools (Harness) die KI benötigt
 
**Minimal (bei vorliegendem Quellcode `v5_lv.c`):**
- Ausführungsumgebung / Shell (Code-Execution)
- `gcc` (zum Bauen und für die C-Gegenprobe)
- `python3` (zum Reimplementieren der Pipeline)
**Zusätzlich im binär-only-Fall (ohne Quelle):**
- Disassembler/Decompiler: Ghidra (idealerweise headless/analyzeHeadless) oder `objdump`/binutils
- optional für automatische Deobfuskation: angr oder miasm (symbolische Ausführung), z3 (Constraint-/MBA-Lösen)
- optional dynamisch: `gdb` (Anti-Debug zur Laufzeit umgehen)
**Was die KI NICHT braucht:** große Rechenleistung, GPU, Brute-Force-Infrastruktur, Netzwerkzugang. Der Angriff ist rein analytisch.
 
Ohne jedes Werkzeug (reiner Chat, Quellcode in den Prompt kopiert) kann ein starkes Modell die Schichten auch allein durch Schlussfolgern abschälen; es fehlt dann nur die Möglichkeit, das Ergebnis selbst auszuführen und zu verifizieren, was die Fehlerquote erhöht. Ein echter Schutz entsteht daraus nicht.
 
## Was eine KI tatsächlich aufhalten würde
 
Nicht mehr Obfuskation, sondern ein anderes **Bedrohungsmodell**:
1. **Serverseitige Validierung / Online-Aktivierung** — das Geheimnis verlässt den Server nie; die KI kann es lokal nicht nachrechnen.
2. **Signaturbasierte Lizenzen** — der Client prüft nur mit öffentlichem Schlüssel; ohne privaten Schlüssel lassen sich keine gültigen Keys erzeugen.
3. **Funktionale Bindung** — Lizenzmaterial als Entschlüsselungsschlüssel echter Programmlogik/-daten, sodass ein falscher Key kein lauffähiges Produkt ergibt (statt nur „denied").
4. Ggf. Packing/Selbstmodifikation + starke Anti-Analyse, um automatisierte statische Pipelines zu erschweren (erhöht aber nur die Kosten, löst das Grundproblem nicht).
## Einschränkung der Einschätzung
 
Diese Bewertung stützt sich auf einen konkreten Durchlauf; das Ergebnis kann je nach Modellstärke und Harness variieren. Die qualitative Aussage bleibt davon unberührt: Gegen eine KI mit üblichem RE-Harness bietet ein rein lokales „Richtig/Falsch"-Lizenzgate praktisch keinen Schutz — unabhängig von der Menge der Verschleierung.