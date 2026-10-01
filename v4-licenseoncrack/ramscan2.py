#!/usr/bin/env python3
# Verfeinerter Scan: zeigt die genauen Adressen der Treffer und
# vergleicht sie mit der Lage von argv[1] (vom Angreifer selbst
# uebergeben) vs. einer echten Rekonstruktion durch das Programm.
import subprocess, time, os, signal

KEY = b'FLAG{4cc3ss_d3n13d}'
p = subprocess.Popen(['./lv', KEY.decode()],
                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
time.sleep(0.15)
os.kill(p.pid, signal.SIGSTOP)

# argv liegt am oberen Stack-Ende; wir lesen /proc/PID/cmdline um die
# Adresse der Argumente zu bestaetigen
with open(f'/proc/{p.pid}/cmdline','rb') as c:
    cmdline = c.read()

addrs=[]
with open(f'/proc/{p.pid}/maps') as m, open(f'/proc/{p.pid}/mem','rb',0) as mem:
    for line in m:
        parts=line.split()
        if 'r' not in parts[1]: continue
        s,e=parts[0].split('-'); s,e=int(s,16),int(e,16)
        if e-s>64*1024*1024: continue
        try:
            mem.seek(s); data=mem.read(e-s)
        except: continue
        off=0
        while True:
            idx=data.find(KEY,off)
            if idx<0: break
            region = parts[5] if len(parts)>5 else '(anon)'
            addrs.append((s+idx, parts[1], region))
            off=idx+1

os.kill(p.pid, signal.SIGCONT)
os.kill(p.pid, signal.SIGKILL); p.wait()

print("Fundstellen des Klartext-Keys im RAM:")
for a,perms,region in addrs:
    print(f"  0x{a:012x}  {perms}  {region}")
print()
print("cmdline-Inhalt (=argv, vom Angreifer selbst uebergeben):")
print("  ", cmdline.replace(b'\x00',b' '))
print()
print("Erklaerung:")
print("  Beide Treffer liegen auf dem [stack] im Bereich von argv/environ.")
print("  Das ist der Key, den der ANGREIFER SELBST als Argument uebergibt")
print("  (einmal in argv, einmal typ. als Kopie in der Shell-Umgebung).")
print("  Das Programm selbst REKONSTRUIERT den Key NICHT -- es gibt keinen")
print("  vom Programm erzeugten 2. Klartext-Puffer wie bei v1 (reveal()).")
