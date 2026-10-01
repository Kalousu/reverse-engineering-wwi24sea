/*
 * lv.c -- "LicenseGuard" v4 (fies, aber per RE loesbar)
 *
 * Aufruf:  ./lv <lizenzschluessel>
 *
 * ZIEL (Lern-Crackme fuer den RE-Kurs): Der naive Angriff gegen v1/v2
 *   -- "Breakpoint hinter reveal(), x/s $buf -> Klartext-Key" -- soll
 *   INS LEERE laufen, der Key aber mit etwas Mehraufwand per Analyse
 *   herausfindbar BLEIBEN. Es ist bewusst KEIN echter Schutzmechanismus,
 *   sondern eine schwerer zu knackende Uebungsaufgabe.
 *
 * WAS v4 ANDERS MACHT ALS v2:
 *
 *   [NODUMP] Kein rekonstruierter Gesamt-Key im RAM.
 *       v1/v2 bauten den vollstaendigen Soll-Key in EINEN Puffer und
 *       verglichen dann. Ein einziger Dump genuegte. v4 prueft
 *       ZEICHENWEISE und verwirft jeden Sollwert sofort wieder
 *       (ueberschreibt ihn), sodass nie der ganze Key zusammenhaengend
 *       im Speicher steht. -> "break; x/s" liefert nur Muell.
 *
 *   [INPUT] Eingabe-abhaengige Pruefung statt gespeichertem Soll-Puffer.
 *       Pro Position i wird die Eingabe transformiert und gegen einen
 *       pro-Byte zur Laufzeit abgeleiteten Zielwert geprueft. Der
 *       Zielwert existiert nur fuer die Dauer EINES Schleifen-
 *       durchlaufs.
 *
 *   [AD] Anti-Debugging (ptrace-Selfcheck + Timing).
 *       Haengt ein Debugger dran, nimmt das Programm einen anderen,
 *       falschen Pfad -- erkennbar und umgehbar, aber laestig.
 *
 *   + die v2-Obfuskierung (MBA, opaque predicates, split constants)
 *     bleibt als "Optik" erhalten.
 *
 * LOESUNGSWEG (fuer die Abgabe, siehe WRITEUP.md):
 *   Die Pruefung pro Byte ist INVERTIERBAR. Wer die Transformation
 *   versteht (statisch in Ghidra oder dynamisch mit Watchpoints auf
 *   das jeweilige Eingabebyte), kann den Sollwert Zeichen fuer Zeichen
 *   zurueckrechnen -- genau die intendierte RE-Uebung.
 */
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
/* Anti-Debug -- plattformabhaengig.
 *
 * WICHTIG: Die ABGABE ist das x86-64 Linux ELF (in der Lima-VM gebaut).
 * Der macOS/ARM-Zweig existiert NUR, damit du die Pruef-LOGIK lokal
 * funktional testen kannst. Ein macOS-Build ist ein Mach-O/ARM64-
 * Binary und entspricht NICHT dem, was reverse-engineert wird. */
#if defined(__linux__)
  #include <sys/syscall.h>
  #include <unistd.h>
  #ifndef SYS_ptrace
    #define SYS_ptrace 101  /* x86-64 */
  #endif
#elif defined(__APPLE__)
  #include <unistd.h>
  /* macOS: PT_DENY_ATTACH verhindert das Anhaengen eines Debuggers.
   * Deklaration ohne <sys/ptrace.h>-Konstantenabhaengigkeit. */
  extern int ptrace(int, pid_t, void*, int);
  #define PT_DENY_ATTACH 31
#else
  #warning "Unbekannte Plattform -- Anti-Debug deaktiviert."
#endif

#define KEYLEN 19

/* ---- [MBA] wie v2: XOR/ADD/SUB verschleiert ---------------------- */
static uint8_t mba_xor(uint8_t a, uint8_t b){ return (uint8_t)((a|b)-(a&b)); }
static uint8_t mba_add(uint8_t a, uint8_t b){ return (uint8_t)((a^b)+((a&b)<<1)); }
static uint8_t mba_sub(uint8_t a, uint8_t b){ return (uint8_t)(a+(uint8_t)(~b)+1); }

/* ---- [OP] opaque predicate: fuer jedes x == 1 -------------------- */
static int op_true(int x){ return (x*x-(x-1)*(x+1))==1; }

/* ---- [CSPLIT] split constants ------------------------------------ */
static const uint8_t CS_SEED[4] = { 0x5A, 0xA5, 0x3C, 0xC3 };
static uint32_t fold_seed(void){
    uint32_t v=0; for(int i=0;i<4;i++) v=(v<<8)|CS_SEED[i]; return v; /* 0x5AA53CC3 */
}

/* ---- [AD] Anti-Debugging ----------------------------------------- */
/* ptrace(TRACEME) schlaegt fehl, wenn bereits ein Debugger dranhaengt.
 * Rueckgabe wird als additiver "Dreh" in die Pruefung eingespeist:
 * unter dem Debugger wird somit ein FALSCHER Zielwert erzeugt. */
static uint8_t debugger_skew(void){
#if defined(__linux__)
    /* PTRACE_TRACEME(0) schlaegt fehl (-1), wenn schon ein Debugger
     * dranhaengt -> dann Pfad verfaelschen. Sonst wieder loesen (DETACH=17). */
    long r = syscall(SYS_ptrace, 0, 0, 0, 0);
    if (r == -1) return 0x6B;
    syscall(SYS_ptrace, 17, 0, 0, 0);
    return 0x00;
#elif defined(__APPLE__)
    /* PT_DENY_ATTACH: wirft unter einem Debugger bzw. verhindert Attach.
     * Rueckgabe -1 signalisiert hier eine bereits bestehende Trace-Situation. */
    int r = ptrace(PT_DENY_ATTACH, 0, 0, 0);
    if (r == -1) return 0x6B;
    return 0x00;
#else
    return 0x00;
#endif
}

/* ---- Pro-Byte-Sollwert: eingabe-/positionsabhaengig -------------- */
/* Dies ist die invertierbare Kern-Transformation. Fuer Position i und
 * Zustand 'prev' (= vorheriges SOLL-Byte, Verkettung) erzeugt sie den
 * erwarteten Wert. Der echte Key ergibt sich, indem man target(i,prev)
 * sukzessive aufloest (siehe WRITEUP). */
static const uint8_t A1[KEYLEN] = {
    /* so gewaehlt, dass target(i,prev,seedb,skew=0)==FLAG{...}[i].
       Liegt NICHT als Klartext-Key vor -- nur als Transformations-
       Konstanten, die zeichenweise verrechnet werden. */
    0xAF,0x3F,0x5A,0xAB,0xE3,0x10,0x88,0x95,0xDB,0x3D,
    0x1F,0x85,0x24,0xC0,0x5E,0xAC,0x51,0xDC,0x3E
};

static uint8_t target_byte(int i, uint8_t prev, uint8_t seedb, uint8_t skew){
    uint8_t t = A1[i];
    t = mba_xor(t, seedb);            /* Seed-Byte */
    t = mba_add(t, (uint8_t)(i*7));   /* Positions-Dreh */
    t = mba_xor(t, prev);             /* Verkettung mit Vorgaenger */
    t = mba_add(t, skew);             /* [AD] Debugger verfaelscht hier */
    return t;
}

/* ---- Konstante-Zeit-ish, aber ZEICHENWEISE mit Wipe -------------- */
int main(int argc, char **argv){
    if (argc != 2){
        fprintf(stderr, "usage: %s <license-key>\n", argv[0]);
        return 1;
    }
    const char *in = argv[1];

    uint8_t skew = debugger_skew();          /* [AD] */
    uint32_t seed = fold_seed();             /* [CSPLIT] 0x5AA53CC3 */

    int ok = 1;
    if (strlen(in) != KEYLEN) ok = 0;

    uint8_t prev = 0x2A;                      /* IV fuer die Verkettung */
    for (int i = 0; i < KEYLEN; i++){
        /* [OP] Scheinverzweigung, immer true */
        uint8_t seedb = op_true(i) ? (uint8_t)(seed >> ((i & 3) * 8)) : 0;

        /* [NODUMP] Sollwert NUR fuer diesen Durchlauf bilden ... */
        uint8_t t = (i < (int)strlen(in)) ? target_byte(i, prev, seedb, skew) : 0;

        /* mit Eingabe vergleichen (MBA-diff), Ergebnis in ok falten */
        uint8_t inb = (i < (int)strlen(in)) ? (uint8_t)in[i] : 0xFF;
        uint8_t diff = mba_xor(inb, t);
        ok &= (diff == 0);

        /* Verkettung fortschreiben, dann Sollwert SOFORT ueberschreiben */
        prev = t;
        volatile uint8_t wipe = (uint8_t)(t ^ 0xFF);
        t = wipe; (void)t;                   /* t ist jetzt Muell */
    }

    if (ok) printf("Access granted. Welcome, licensed user.\n");
    else    printf("Access denied.\n");
    return ok ? 0 : 1;
}
