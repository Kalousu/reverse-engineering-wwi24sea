## Anleitung: Reverse Engineering Schritt für Schritt
 
Jeder Schritt ist mit Befehl und erwarteter Ausgabe angegeben und direkt reproduzierbar.
 
### Schritt 0 — Bauen & Triage
 
```console
$ ./build.sh                         # baut License_Validator_x86_64 und _ARM
# (alternativ direkt:)  gcc -O2 -o License_Validator_x86_64 v5_lv.c
 
$ file License_Validator_x86_64
ELF 64-bit LSB pie executable, x86-64, dynamically linked, not stripped
$ ./License_Validator_x86_64 AAAAAAAAAAAAAAAAAAA
Access denied.
```
 
Die Binaries sind **nicht gestrippt** → Symbole wie `reveal`, `target_byte`, `debugger_skew` sind direkt sichtbar (`nm License_Validator_x86_64`). In Ghidra sieht man sofort, dass genau **ein** Vergleich (`h_got == h_want`) über „granted/denied" entscheidet. Einstieg der Analyse = die Schleife, die zu `ok` führt.
 
### Schritt 1 — Format/Vorfilter verstehen
 
`lc_precheck`: Länge == 19, Zeichensatz `[A-Za-z0-9{}!@#_-]`, Prüfsumme (`lc_checksum`) im Band `0x20000000…0xDFFFFFFF`. Das grenzt nur ein; der echte Key erfüllt es.
 
### Schritt 2 — Datenfluss erkennen (die Schwäche)
 
In Ghidra/am Quelltext erkennt man: `target_byte(...)` hängt **nicht** von `in[]` ab. Daraus folgt, dass der erwartete Key allein aus `A1[]` + Konstanten bestimmt ist (siehe oben).
 
### Schritt 3 — Konstanten extrahieren (`[CSPLIT]`)
 
`fold_const` setzt vier Bytes big-endian zusammen (`CS_PERM = {0,1,2,3}`):
 
```
g_a  = 0xC0DE1337     g_b = 0x1337C0DE     seed = 0x5AA53CC3
```
 
`op_always_true(42)` ist konstant wahr → `g_a`/`g_b` werden nicht invertiert.
 
### Schritt 4 — Verschleierung abschälen
 
- **`[MBA]`:** `mba_xor == ^`, `mba_add == +`, `mba_sub == -`, `rr/rl == ror/rol` (durch alle 256×256 Paare oder algebraisch nachweisbar).
- **`[CFF]`+`[IND]`:** Der Zustandsautomat in `reveal()` führt die Stufen linear aus: `stage1_lcg → stage2_shift → stage3_acc → stage4_inv → stage5_vm`. Die maskierten Pointer (`mask_ptr`/`unmask_ptr`) heben sich auf.
- **`[VM]`:** `VM_PROG = {LOADX, ROR_PV, XOR_PV, SUB_S, STORE}` bedeutet pro Byte: `x = ror(b[i], pv&7); x ^= pv; x -= s; pv = b[i]` mit `s = f0()`.
- **`[OP]`:** `op_always_true` ⇒ 1, `op_always_false` ⇒ 0.
### Schritt 5 — Schlüssel rekonstruieren
 
**Weg A — eigenständiges Keygen `solve.py`** (reimplementiert Schritt 3+4 in Python, braucht die Quelle nicht; gilt für ARM **und** x86_64, weil nur Konstanten eingehen):
 
```console
$ python3 solve.py
KEY: FLAG{4cc3ss_d3n13d}
HEX: 46 4c 41 47 7b 34 63 63 33 73 73 5f 64 33 6e 31 33 64 7d
```
 
**Weg B — Gegenprobe `keygen.c`** (dieselbe Quelldatei, nur `main()` ersetzt; schließt Reimplementierungsfehler aus):
 
```console
$ gcc -O2 -o keygen keygen.c && ./keygen
KEY (ascii): FLAG{4cc3ss_d3n13d}
precheck   : PASS
```
 
### Schritt 6 — Verifikation gegen das unveränderte Binary
 
```console
$ ./License_Validator_x86_64 "FLAG{4cc3ss_d3n13d}"
Access granted. Welcome, licensed user.
$ ./License_Validator_x86_64 "GLAG{4cc3ss_d3n13d}"   # ein Byte verändert
Access denied.
```
 
### Schritt 7 (optional) — Anti-Debug neutralisieren
 
Für das reine Lösen nicht nötig (Weg A/B sind statisch). Wer das Programm **unter einem Debugger** laufen lassen will, muss `ad_skew`/`t_skew` auf 0 zwingen.
 
Wichtig: `debugger_skew()` ruft `ptrace` über den **rohen `syscall()`** auf → es gibt keinen `ptrace`-PLT-Eintrag, ein `LD_PRELOAD`-Hook auf libc-`ptrace()` ist also wirkungslos:
 
```console
$ objdump -d License_Validator_x86_64 | grep -i ptrace    # -> kein ptrace@plt
```
 
Saubere Lösung — Binary-Patch (x86_64), setzt beide Funktionen auf `xor eax,eax; ret`:
 
```console
$ python3 patch.py License_Validator_x86_64 License_Validator_x86_64_patched
debugger_skew  fileoff=0x... orig=f30f1e -> 31c0c3
timing_skew    fileoff=0x... orig=f30f1e -> 31c0c3
$ ./License_Validator_x86_64_patched "FLAG{4cc3ss_d3n13d}"
Access granted. Welcome, licensed user.
```
 
> Hinweis ARM: `patch.py` findet die Offsets per `nm` selbst, aber die eingesetzten Opcodes `31 C0 C3` sind x86_64. Auf aarch64 lautet „return 0" `mov w0, #0; ret` (`00 00 80 52  C0 03 5F D6`). Der **statische** Weg (`solve.py`) umgeht das Anti-Debugging dagegen komplett und funktioniert für beide Architekturen unverändert.
 
### Reproduktions-Checkliste (copy-paste)
 
```console
./build.sh
python3 solve.py                                   # -> FLAG{4cc3ss_d3n13d}
gcc -O2 -o keygen keygen.c && ./keygen             # Gegenprobe
./License_Validator_x86_64 "FLAG{4cc3ss_d3n13d}"   # -> Access granted.
```
 