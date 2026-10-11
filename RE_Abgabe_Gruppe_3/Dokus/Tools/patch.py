#!/usr/bin/env python3
# patch.py -- neutralisiert die Anti-Debug-/Timing-Pruefungen in einem
# NICHT-gestrippten LicenseGuard-Build, indem debugger_skew() und
# timing_skew() auf "return 0" (xor eax,eax ; ret) gesetzt werden.
# Danach laeuft der gueltige Schluessel auch unter einem Debugger durch.
#
#   Aufruf:  python3 patch.py <binary_in> <binary_out>
import sys, os, subprocess

def text_vma_off(path):
    for ln in subprocess.check_output(['objdump','-h',path]).decode().splitlines():
        if ' .text' in ln:
            p = ln.split(); return int(p[3],16), int(p[5],16)
    raise SystemExit("keine .text-Section gefunden")

def sym_addr(path, name):
    for ln in subprocess.check_output(['nm',path]).decode().splitlines():
        p = ln.split()
        if len(p)>=3 and p[2]==name: return int(p[0],16)
    raise SystemExit(f"Symbol {name} nicht gefunden (gestripptes Binary? dann manuell patchen)")

def main():
    src, dst = sys.argv[1], sys.argv[2]
    vma, off = text_vma_off(src)
    data = bytearray(open(src,'rb').read())
    PATCH = bytes([0x31,0xC0,0xC3])            # xor eax,eax ; ret
    for name in ('debugger_skew','timing_skew'):
        fo = sym_addr(src,name) - vma + off
        print(f"{name:14s} fileoff=0x{fo:x} orig={data[fo:fo+3].hex()} -> {PATCH.hex()}")
        data[fo:fo+3] = PATCH
    open(dst,'wb').write(data); os.chmod(dst,0o755)
    print("geschrieben:", dst)

if __name__ == '__main__':
    main()
