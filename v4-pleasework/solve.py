#!/usr/bin/env python3
# solve.py -- LOESUNG fuer v4. Zeigt, dass das Crackme per RE knackbar ist:
# rechnet den gueltigen Key allein aus den statisch extrahierbaren
# Konstanten (A1[], seed, IV) zurueck -- ohne ihn je als Klartext
# dumpen zu muessen.
#
# Ein Analyst gewinnt diese Werte so:
#   - A1[]  : steht als Byte-Array in .rodata (in Ghidra sichtbar)
#   - seed  : CS_SEED -> 0x5AA53CC3 (split constant, zusammengesetzt)
#   - IV    : prev-Startwert 0x2A (im Code sichtbar)
#   - skew  : 0 im Nicht-Debugger-Pfad (Anti-Debug muss umgangen werden)
# und invertiert dann target_byte() Position fuer Position.

A1=[0xAF,0x3F,0x5A,0xAB,0xE3,0x10,0x88,0x95,0xDB,0x3D,
    0x1F,0x85,0x24,0xC0,0x5E,0xAC,0x51,0xDC,0x3E]
seed=0x5AA53CC3
skew=0x00
prev=0x2A

key=[]
for i in range(19):
    seedb=(seed>>((i&3)*8))&0xFF
    # target = ((((A1[i]^seedb)+i*7)^prev)+skew)  == gesuchtes Key-Byte
    t=A1[i]
    t=(t^seedb)&0xFF
    t=(t+(i*7))&0xFF
    t=(t^prev)&0xFF
    t=(t+skew)&0xFF
    key.append(t)
    prev=t    # Verkettung nutzt das gerade bestimmte Soll-Byte

s=bytes(key)
print("Rueckgerechneter Key:", s.decode('latin1'))
print("Als Hex:", s.hex())
