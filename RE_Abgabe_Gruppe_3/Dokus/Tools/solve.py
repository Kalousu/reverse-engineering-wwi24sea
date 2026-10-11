#!/usr/bin/env python3
# Eigenstaendiger Keygen - reimplementiert die LicenseGuard-v5-Logik komplett.
# Benoetigt die Originalquelle NICHT; nur die extrahierten Konstanten.
M = 0xFF
def bxor(a,b): return (a|b)-(a&b) & M          # == a^b
def badd(a,b): return ((a^b)+((a&b)<<1)) & M   # == a+b
def bsub(a,b): return (a+((~b)&M)+1) & M       # == a-b
def ror(v,r): r&=7; return badd((v>>r)&M, (v<<(8-r))&M)
def rol(v,r): r&=7; return badd((v<<r)&M, (v>>(8-r))&M)

A0=[0x9E,0x37,0x79,0xB9,0x7F,0x4A,0x7C,0x15,0xF3,0x9C,0xC0,0x60,0x51,0x2D,0xA3,0x1B]
A1=[0xCC,0xB7,0x7F,0xDD,0x1A,0x79,0xF0,0x15,0xCB,0x56,0xA6,0x62,0xFB,0x89,0xA0,0x8E,0x91,0x7F,0x0C]
g_a=0xC0DE1337; g_b=0x1337C0DE; seed=0x5AA53CC3   # aus CSPLIT-Scherben zusammengesetzt

def mk():
    T=[(i*167+13)&M for i in range(256)]; k=0x5A
    for i in range(256):
        k=(k+T[i]+i)&M; T[i],T[k]=T[k],T[i]
    return T
def mki(T):
    iv=[0]*256
    for i in range(256): iv[T[i]]=i
    return iv
def f0():
    s=0
    for i in range(16): s=bxor(s,A0[i]); s=rol(s,3)
    return s

def reveal(b):
    T=mk(); iv=mki(T); n=len(b)
    # stage1_lcg
    s=g_b
    for i in range(n):
        s=(s*1103515245+12345)&0xFFFFFFFF; b[i]=bxor(b[i],(s>>24)&M)
    # stage2_shift
    c=g_a
    for i in range(n):
        b[i]=bsub(b[i], c&M); c=((c>>8)|(c<<24))&0xFFFFFFFF
    # stage3_acc
    acc=0x3C
    for i in range(n):
        cur=b[i]; b[i]=bxor(cur,acc); acc=(acc*33+cur)&M
    # stage4_inv
    pv=0xA5
    for i in range(n):
        y=b[i]; b[i]=bsub(iv[y],pv); pv=y
    # stage5_vm
    s=f0(); pv=s
    for i in range(n):
        x=b[i]; cur=x; x=ror(x,pv&7); x=bxor(x,pv); x=bsub(x,s); b[i]=x; pv=cur
    return b

def keygen(ad_skew=0, t_skew=0):
    rbuf=reveal(A1[:])
    prev=0x2A; key=[]
    for i in range(19):
        seedb=(seed>>((i&3)*8))&M
        t=rbuf[i]; t=bxor(t,seedb); t=badd(t,(i*7)&M); t=bxor(t,prev)
        t=badd(t,ad_skew); t=badd(t,t_skew)
        key.append(t); prev=t
    return bytes(key)

k=keygen()
print("KEY:", k.decode('latin1'))
print("HEX:", k.hex(' '))
