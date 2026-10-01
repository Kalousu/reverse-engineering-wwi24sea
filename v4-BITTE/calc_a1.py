#!/usr/bin/env python3
# Rechnet die A1[]-Bytes so, dass target_byte(i,prev,seedb,skew=0) == key[i]
# ergibt. Also die INVERSE der Transformation in target_byte.
KEY = b'FLAG{4cc3ss_d3n13d}'
assert len(KEY)==19

def mxor(a,b): return (a^b)&0xFF          # mba_xor == xor
def madd(a,b): return (a+b)&0xFF          # mba_add == add
def msub(a,b): return (a-b)&0xFF          # mba_sub == sub

seed = 0x5AA53CC3
skew = 0x00   # ohne Debugger

# target_byte: t=A1[i]; t^=seedb; t+=i*7; t^=prev; t+=skew
# wir wollen target==KEY[i]. prev-Kette nutzt die SOLL-Bytes (=KEY),
# weil prev=t am Ende gesetzt wird und t==KEY[i] sein soll.
A1=[]
prev=0x2A
for i in range(19):
    seedb = (seed >> ((i&3)*8)) & 0xFF
    want = KEY[i]
    # invertiere: want = ((((A1 ^ seedb) + i*7) ^ prev) + skew)
    t = msub(want, skew)
    t = mxor(t, prev)
    t = msub(t, (i*7)&0xFF)
    a1 = mxor(t, seedb)
    A1.append(a1)
    prev = want   # naechste Verkettung nutzt das SOLL-Byte

print("static const uint8_t A1[KEYLEN] = {")
for r in range(0,19,10):
    chunk=A1[r:r+10]
    print("    "+",".join(f"0x{b:02X}" for b in chunk)+("," if r+10<19 else ""))
print("};")

# Gegenprobe
prev=0x2A
for i in range(19):
    seedb=(seed>>((i&3)*8))&0xFF
    t=A1[i]; t=mxor(t,seedb); t=madd(t,(i*7)&0xFF); t=mxor(t,prev); t=madd(t,skew)
    assert t==KEY[i], f"mismatch at {i}: {t:02x} != {KEY[i]:02x}"
    prev=t
print("\n# Gegenprobe OK: target()==KEY fuer alle 19 Bytes")
