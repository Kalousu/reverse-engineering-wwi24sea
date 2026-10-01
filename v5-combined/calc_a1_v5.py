#!/usr/bin/env python3
"""
calc_a1_v5.py -- berechnet A1[] fuer v5_lv.c

Die v5-Pruefung macht pro Byte i:
  revealed_i  = reveal(A1)[i]          (5 Stufen: lcg, shift, acc, inv, vm)
  t           = target_byte(revealed_i, i, seedb, prev, ad_skew=0, t_skew=0)
  expected:     t == KEY[i]

Invertiert:
  revealed_i  = inv_target_byte(KEY[i], i, seedb, prev)
  A1[i]       = inv_reveal(revealed_i)[i]

Da reveal() auf dem gesamten Puffer operiert, muessen wir inv_reveal()
auf dem ganzen Puffer invertieren.
"""

KEY    = b"FLAG{4cc3ss_d3n13d}"
KEYLEN = 19
assert len(KEY) == KEYLEN

# ---- Konstanten (muessen mit v5_lv.c uebereinstimmen) ---------------
G_A  = 0xC0DE1337
G_B  = 0x1337C0DE
SEED = 0x5AA53CC3
IV   = 0x2A

# ---- MBA-Helfer ------------------------------------------------------
def mba_xor(a, b): return ((a | b) - (a & b)) & 0xFF
def mba_add(a, b): return ((a ^ b) + ((a & b) << 1)) & 0xFF
def mba_sub(a, b): return (a + (~b & 0xFF) + 1) & 0xFF

def rr(v, r):
    r &= 7
    return mba_add((v >> r) & 0xFF, (v << (8 - r)) & 0xFF)
def rl(v, r):
    r &= 7
    return mba_add((v << r) & 0xFF, (v >> (8 - r)) & 0xFF)

# ---- S-Box (identisch zu mk() in C) ---------------------------------
T = [(i * 167 + 13) & 0xFF for i in range(256)]
k = 0x5A
for i in range(256):
    k = (k + T[i] + i) & 0xFF
    T[i], T[k] = T[k], T[i]
IV_BOX = [0] * 256
for i in range(256):
    IV_BOX[T[i]] = i

# ---- f0() -----------------------------------------------------------
A0 = [0x9E,0x37,0x79,0xB9,0x7F,0x4A,0x7C,0x15,
      0xF3,0x9C,0xC0,0x60,0x51,0x2D,0xA3,0x1B]
def f0():
    s = 0
    for b in A0:
        s = mba_xor(s, b)
        s = rl(s, 3)
    return s

# ---- Fuenf Stufen (forward, auf Puffer) -----------------------------
def stage1_lcg(buf):
    s = G_B
    out = []
    for b in buf:
        s = (s * 1103515245 + 12345) & 0xFFFFFFFF
        out.append(mba_xor(b, (s >> 24) & 0xFF))
    return out

def stage2_shift(buf):
    c = G_A
    out = []
    for b in buf:
        out.append(mba_sub(b, c & 0xFF))
        c = ((c >> 8) | (c << 24)) & 0xFFFFFFFF
    return out

def stage3_acc(buf):
    acc = 0x3C
    out = []
    for b in buf:
        p = mba_xor(b, acc)
        acc = (acc * 33 + b) & 0xFF
        out.append(p)
    return out

def stage4_inv(buf):
    pv = 0xA5
    out = []
    for b in buf:
        ix = IV_BOX[b]
        out.append(mba_sub(ix, pv))
        pv = b
    return out

def vm_run(buf, s):
    pv = s
    out = list(buf)
    for i in range(len(buf)):
        x   = out[i]
        cur = x
        x   = rr(x, pv & 7)
        x   = mba_xor(x, pv)
        x   = mba_sub(x, s)
        out[i] = x
        pv  = cur
    return out

def stage5_vm(buf):
    return vm_run(buf, f0())

def reveal(buf):
    b = list(buf)
    b = stage1_lcg(b)
    b = stage2_shift(b)
    b = stage3_acc(b)
    b = stage4_inv(b)
    b = stage5_vm(b)
    return b

# ---- Inverse Stufen -------------------------------------------------
def inv_stage5_vm(buf):
    s  = f0()
    pv = s
    out = list(buf)
    for i in range(len(buf)):
        y = out[i]
        y = mba_add(y, s)      # undo sub
        y = mba_xor(y, pv)     # undo xor
        x = rl(y, pv & 7)      # undo ror
        out[i] = x
        pv = x                 # pv_neu = original in[i]
    return out

def inv_stage4_inv(buf):
    # forward: out[i] = mba_sub(IV_BOX[b], pv);  pv = b
    # inverse: IV_BOX[b] = mba_add(out[i], pv) -> b = T[mba_add(out[i], pv)]
    pv = 0xA5
    out = list(buf)
    for i in range(len(buf)):
        ix = mba_add(out[i], pv)  # = IV_BOX[original_b]
        b  = T[ix]                # T ist die Vorwaerts-S-Box
        pv = b
        out[i] = b
    return out

def inv_stage3_acc(buf):
    # forward: p = xor(b, acc); acc = (acc*33 + b)&0xFF
    # inverse: b = xor(p, acc) -- aber acc haengt von b ab!
    # acc_neu = (acc*33 + b) & 0xFF; b = xor(p, acc_alt)
    acc = 0x3C
    out = list(buf)
    for i in range(len(buf)):
        p = out[i]
        b = mba_xor(p, acc)
        acc = (acc * 33 + b) & 0xFF
        out[i] = b
    return out

def inv_stage2_shift(buf):
    # forward: out[i] = mba_sub(b, kb); c rotiert
    # inverse: b = mba_add(out[i], kb)
    c = G_A
    out = list(buf)
    for i in range(len(buf)):
        out[i] = mba_add(out[i], c & 0xFF)
        c = ((c >> 8) | (c << 24)) & 0xFFFFFFFF
    return out

def inv_stage1_lcg(buf):
    # forward: out[i] = xor(b, (s>>24)&0xFF); xor ist selbstinvers
    s = G_B
    out = list(buf)
    for i in range(len(buf)):
        s = (s * 1103515245 + 12345) & 0xFFFFFFFF
        out[i] = mba_xor(out[i], (s >> 24) & 0xFF)
    return out

def inv_reveal(buf):
    b = list(buf)
    b = inv_stage5_vm(b)
    b = inv_stage4_inv(b)
    b = inv_stage3_acc(b)
    b = inv_stage2_shift(b)
    b = inv_stage1_lcg(b)
    return b

# ---- target_byte (forward, skew=0) ----------------------------------
def target_byte(revealed_i, i, seedb, prev, ad_skew=0, t_skew=0):
    t = revealed_i
    t = mba_xor(t, seedb)
    t = mba_add(t, (i * 7) & 0xFF)
    t = mba_xor(t, prev)
    t = mba_add(t, ad_skew)
    t = mba_add(t, t_skew)
    return t

def inv_target_byte(key_byte, i, seedb, prev):
    t = key_byte
    t = mba_sub(t, 0)          # t_skew = 0
    t = mba_sub(t, 0)          # ad_skew = 0
    t = mba_xor(t, prev)       # xor selbstinvers
    t = mba_sub(t, (i * 7) & 0xFF)
    t = mba_xor(t, seedb)
    return t

# ---- Schritt 1: revealed[] berechnen --------------------------------
# Wir wollen: target_byte(revealed[i], ...) == KEY[i]
# Also: revealed[i] = inv_target_byte(KEY[i], ...)
revealed = []
prev = IV
for i in range(KEYLEN):
    seedb = (SEED >> ((i & 3) * 8)) & 0xFF
    r = inv_target_byte(KEY[i], i, seedb, prev)
    revealed.append(r)
    # prev = target_byte(r, i, seedb, prev_alt) == KEY[i]
    prev = KEY[i]

# ---- Schritt 2: A1[] = inv_reveal(revealed) -------------------------
A1 = inv_reveal(revealed)

# ---- Verifikation ---------------------------------------------------
revealed_check = reveal(list(A1))
assert revealed_check == revealed, "reveal-Inversion fehlgeschlagen!"

prev = IV
for i in range(KEYLEN):
    seedb = (SEED >> ((i & 3) * 8)) & 0xFF
    t = target_byte(revealed_check[i], i, seedb, prev)
    assert t == KEY[i], f"Byte {i}: erwartet {KEY[i]:02x}, got {t:02x}"
    prev = KEY[i]
print("Verifikation OK -- alle Bytes stimmen.")

# ---- Ausgabe --------------------------------------------------------
print(f"\nstatic const uint8_t A1[{KEYLEN}] = {{")
row = "    " + ",".join(f"0x{b:02X}" for b in A1[:10])
print(row + ",")
row = "    " + ",".join(f"0x{b:02X}" for b in A1[10:])
print(row)
print("};")
