# v2-secure – LicenseGuard (stark gehärtete Fassung)

`v2_lv.c` ist funktional **identisch** zur unverschleierten Referenzversion — derselbe Lizenzschlüssel wird akzeptiert. Nur die *Lesbarkeit* für einen Analysten wurde massiv reduziert. `build.sh` strippt zusätzlich alle Debugsymbole.

---

## Eingesetzte Obfuskationstechniken

### [CFF] Control-Flow-Flattening

`reveal()` ist keine sequenzielle Abfolge sichtbarer Schleifenblöcke mehr, sondern eine einzige `while`-Schleife über einen Zustandsautomaten mit `switch`. Im Disassembler sieht man nur einen generischen Dispatcher (`ST_INIT → ST_STAGE1_LCG → … → ST_DONE`); die Reihenfolge der fünf Transformationsstufen ist am Kontrollfluss nicht mehr direkt ablesbar. Zähler (`step`) und Zustandsvariable (`state`) sind die einzigen Indizien für die echte Sequenz.

### [OP] Opaque Predicates

`op_always_true(x)` wertet für **jedes** ganzzahlige `x` zu `1` aus, weil `x² − (x−1)(x+1) = 1` eine algebraische Identität ist. Im Code erscheinen Aufrufe wie `op_always_true(42)` (in `init_state`) und `op_always_true(step)` (im Dispatcher) als echte Laufzeitentscheidungen mit zwei Zweigen — der `else`-Zweig ist jedoch toter Code. Ein Analyst muss die Identität erst beweisen, bevor er ihn ausschließen darf.

### [MBA] Mixed Boolean-Arithmetic

Alle XOR-, ADD- und SUB-Operationen auf `uint8_t` laufen über die Hilfsfunktionen `mba_xor`, `mba_add` und `mba_sub`, die die jeweilige Operation durch äquivalente Bit-Tricks ersetzen:

| Operation | Formel im Code |
|-----------|----------------|
| `a ^ b`   | `(a \| b) - (a & b)` |
| `a + b`   | `(a ^ b) + 2*(a & b)` (Halbaddierer-Identität) |
| `a - b`   | `a + (~b) + 1` |

Gleiches Prinzip gilt für die Rotationen `rr`/`rl` und den Konstantzeitvergleich `eq_ct`. Decompiler erkennen diese Muster in der Regel nicht als einfache Arithmetic-Operationen.

### [IND] Indirekte Aufrufe

Die vier Stage-Funktionen (`stage1_lcg`, `stage2_shift`, `stage3_acc`, `stage4_inv`) werden nicht direkt aufgerufen, sondern über eine Funktionszeigertabelle (`table[4]`), deren Einträge mit einem laufzeitberechneten Schlüssel `pk = g_a ^ g_b ^ 0xA5A5A5A5` XOR-maskiert sind. Im Binary stehen in der Tabelle nur sinnlos aussehende Adressen; der statische Call-Graph zeigt keine direkten Aufrufkanten mehr. Erst im Dispatcher werden die Pointer mit `unmask_ptr()` wiederhergestellt und gesprungen.

### [CSPLIT] Constant Splitting

Die Konstanten `0xC0DE1337` und `0x1337C0DE` liegen **nirgends** als zusammenhängendes 32-bit-Literal im Binary. Stattdessen existieren sie als Byte-Scherben in den Arrays `CS_A` und `CS_B`. Die Funktion `fold_const()` setzt sie erst zur Laufzeit über eine (strukturell immer identische) Permutation wieder zusammen. Ein `strings`- oder Binär-Suche nach dem Literal findet nichts.

### [VM] Mini-Bytecode-Interpreter

Die letzte Transformationsstufe (Rotate/XOR/Sub pro Byte) läuft nicht als C-Schleife, sondern als kleines Bytecode-Programm (`VM_PROG[]`), das von `vm_run_stage5()` interpretiert wird. Die Opcodes sind bewusst nichtssagend benannt (`OP_LOADX`, `OP_ROR_PV`, …). Im Disassembler sieht man nur eine generische Interpreter-Schleife — die eigentliche Operation (Rotate → XOR → Sub) steckt im Datensegment, nicht im Codefluss.

### [JUNK] Dead Code

In der Dispatcher-Schleife wird pro Iteration eine `volatile`-Variable `noise` als Pseudoprüfsumme des aktuellen Zustands berechnet (`state * 2654435761 ^ (noise >> 13)`). Das Ergebnis wird mit `(void)noise` explizit verworfen und hat keinen Einfluss auf das Programm. Beim Tracing sieht die Berechnung jedoch wie sicherheitsrelevante Logik aus.

---

## Zusammenspiel der Techniken

```
main()
  └─ init_state()          [CSPLIT] + [OP]  – Konstanten falten, tote Verzweigung
  └─ reveal()              [CFF]            – Dispatcher-Schleife
       ├─ ST_INIT          [OP]             – immer-wahre Eintrittsbedingung
       ├─ ST_STAGE1_LCG    [IND] + [MBA]    – indirekter Aufruf, mba_xor
       ├─ ST_STAGE2_SHIFT  [IND] + [MBA]    – indirekter Aufruf, mba_sub
       ├─ ST_STAGE3_ACC    [IND] + [MBA]    – indirekter Aufruf, mba_xor
       ├─ ST_STAGE4_INV    [IND] + [MBA]    – indirekter Aufruf, mba_sub
       └─ ST_STAGE5_VM     [VM]  + [MBA]    – Bytecode-Interpreter
       (jede Iteration)    [JUNK]           – noise-Berechnung, nie benutzt
```

---

## Hinweis für die Übung

Jede Technik ist einzeln invertierbar bzw. durch Emulation/symbolische Ausführung auflösbar — echte Sicherheit entsteht daraus nicht, nur ein deutlich höherer Analyseaufwand. Ziel der Übung ist, diese Muster im Disassembler/Decompiler zu erkennen und systematisch zu eliminieren.
