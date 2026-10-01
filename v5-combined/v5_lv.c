/*
 * licenseguard.c -- LicenseGuard v5
 *
 * Aufruf:  ./lv <lizenzschluessel>
 */

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>

#if defined(__linux__)
  #include <sys/syscall.h>
  #include <unistd.h>
  #ifndef SYS_ptrace
    #define SYS_ptrace 101
  #endif
#elif defined(__APPLE__)
  #include <unistd.h>
  extern int ptrace(int, pid_t, void*, int);
  #define PT_DENY_ATTACH 31
#endif

#define KEYLEN 19

/* ------------------------------------------------------------------ */
/* Rohdaten                                                            */
/* ------------------------------------------------------------------ */
/* A0: wie v2, fuer f0() */
static const uint8_t A0[16] = {
    0x9E,0x37,0x79,0xB9,0x7F,0x4A,0x7C,0x15,
    0xF3,0x9C,0xC0,0x60,0x51,0x2D,0xA3,0x1B
};

/* A1: vorberechneter Eingabepuffer */
static const uint8_t A1[KEYLEN] = {
    0xCC,0xB7,0x7F,0xDD,0x1A,0x79,0xF0,0x15,0xCB,0x56,
    0xA6,0x62,0xFB,0x89,0xA0,0x8E,0x91,0x7F,0x0C
};

/* [CSPLIT] Konstanten als Scherben */
static const uint8_t CS_A[4]    = { 0xC0, 0xDE, 0x13, 0x37 }; /* 0xC0DE1337 */
static const uint8_t CS_B[4]    = { 0x13, 0x37, 0xC0, 0xDE }; /* 0x1337C0DE */
static const uint8_t CS_SEED[4] = { 0x5A, 0xA5, 0x3C, 0xC3 }; /* 0x5AA53CC3 */
static const uint8_t CS_PERM[4] = { 0, 1, 2, 3 };

static uint8_t  T[256];
static uint8_t  g_t  = 0;
static uint32_t g_a  = 0, g_b = 0;

/* ------------------------------------------------------------------ */
/* [MBA]                                                               */
/* ------------------------------------------------------------------ */
static uint8_t mba_xor(uint8_t a, uint8_t b) { return (uint8_t)((a | b) - (a & b)); }
static uint8_t mba_add(uint8_t a, uint8_t b) { return (uint8_t)((a ^ b) + ((a & b) << 1)); }
static uint8_t mba_sub(uint8_t a, uint8_t b) { return (uint8_t)(a + (uint8_t)(~b) + 1); }

static uint8_t rr(uint8_t v, int r) {
    r &= 7;
    return mba_add((uint8_t)(v >> r), (uint8_t)(v << (8 - r)));
}
static uint8_t rl(uint8_t v, int r) {
    r &= 7;
    return mba_add((uint8_t)(v << r), (uint8_t)(v >> (8 - r)));
}

/* ------------------------------------------------------------------ */
/* [OP] Opaque Predicates                                              */
/* ------------------------------------------------------------------ */
static int op_always_true(int x)  { return (x * x - (x - 1) * (x + 1)) == 1; }
static int op_always_false(unsigned x) __attribute__((unused));
static int op_always_false(unsigned x) { return (int)((x | ~x) + 1u) != 0 ? 0 : 0; }

/* ------------------------------------------------------------------ */
/* Lizenz-Format-Validierung (Strukturpruefung)                        */
/* ------------------------------------------------------------------ */

/* Erlaubte Zeichenklassen im Schluessel */
static const char LC_VALID_CHARS[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                                     "abcdefghijklmnopqrstuvwxyz"
                                     "0123456789"
                                     "{}!@#_-";

/* Prueft ob ein Byte zu einer erlaubten Zeichenklasse gehoert.
 * Wird vor der eigentlichen Verifikation aufgerufen. */
static int lc_check_charset(const char *s, int len) {
    for (int i = 0; i < len; i++) {
        int found = 0;
        for (int j = 0; LC_VALID_CHARS[j]; j++) {
            if (s[i] == LC_VALID_CHARS[j]) { found = 1; break; }
        }
        if (!found) return 0;
    }
    return 1;
}

/* Einfache Pruefsumme ueber den Schluessel -- wird als Vorfilter
 * eingesetzt bevor die teure kryptografische Pruefung laeuft. */
static uint32_t lc_checksum(const uint8_t *data, int len) {
    uint32_t h = 0x12345678u;
    for (int i = 0; i < len; i++) {
        h ^= (uint32_t)data[i] << (i & 0x18);
        h  = (h << 5) | (h >> 27);
        h += (uint32_t)data[i] * 0x9E3779B9u;
    }
    return h;
}

/* Erwartet fuer einen gueltigen Schluessel:
 * Pruefsumme im Bereich [0x20000000, 0xDFFFFFFF].
 * Filtert offensichtlich falsche Eingaben fruehzeitig aus. */
static int lc_precheck(const char *in, int len) {
    if (len != KEYLEN) return 0;
    if (!lc_check_charset(in, len)) return 0;
    uint32_t cs = lc_checksum((const uint8_t *)in, len);
    return (cs >= 0x20000000u && cs <= 0xDFFFFFFFu);
}

/* ------------------------------------------------------------------ */
/* Sekundaere Transformationspipeline (Integritaetspfad)               */
/* ------------------------------------------------------------------ */

/* Zweite S-Box fuer den Integritaetspfad -- unabhaengig von T[] */
static uint8_t T2[256];
static uint8_t g_t2 = 0;

static void mk2(void) {
    for (int i = 0; i < 256; i++) T2[i] = (uint8_t)((i * 251 + 97) & 0xFF);
    uint8_t k = 0xA3;
    for (int i = 0; i < 256; i++) {
        k = (uint8_t)(k + T2[i] + (uint8_t)(i * 3));
        uint8_t tmp = T2[i]; T2[i] = T2[k]; T2[k] = tmp;
    }
    g_t2 = 1;
}

/* Wendet eine Diffusionsschicht auf einen Puffer an.
 * Basiert auf einem nichtlinearen Rueckkopplungsregister. */
static void diffuse(uint8_t *b, int n) {
    if (!g_t2) mk2();
    uint8_t fb = 0xC3;
    for (int i = 0; i < n; i++) {
        uint8_t x = mba_xor(b[i], T2[fb]);
        x   = mba_add(x, (uint8_t)(i * 13 + 7));
        fb  = mba_add(fb, b[i]);
        b[i] = x;
    }
}

/* Berechnet einen 32-Bit Digest ueber einen transformierten Puffer.
 * Wird intern zur Integritaetspruefung der Transformationskette
 * verwendet. Gibt 0 zurueck wenn der Puffer korrumpiert erscheint. */
static uint32_t integrity_digest(const uint8_t *b, int n) {
    uint32_t d = 0xABCD1234u;
    for (int i = 0; i < n; i++) {
        d ^= (uint32_t)b[i];
        d  = (d * 0x45D9F3Bu) ^ (d >> 16);
    }
    return d;
}

/* Zweistufige Eingabetransformation fuer den Integritaetspfad.
 * Laeuft parallel zur Hauptpruefung und verifiziert die interne
 * Konsistenz der Transformationskette. */
static int verify_integrity(const uint8_t *raw, int n) {
    uint8_t tmp[KEYLEN];
    for (int i = 0; i < n; i++) tmp[i] = raw[i];
    diffuse(tmp, n);
    uint32_t d = integrity_digest(tmp, n);
    /* Integritaet gilt als gegeben wenn Digest in erwartetem Band liegt */
    return (d & 0xFF) != 0x00;
}

/* ------------------------------------------------------------------ */
/* Lizenzklassen-Decoder                                               */
/* ------------------------------------------------------------------ */

/* Interne Lizenzklasse -- bestimmt Berechtigungsstufe */
typedef enum {
    LC_INVALID   = 0,
    LC_TRIAL     = 1,
    LC_STANDARD  = 2,
    LC_EXTENDED  = 3,
    LC_ENTERPRISE = 4
} license_class_t;

/* Dekodiert die Lizenzklasse aus dem ersten und letzten Byte des Keys.
 * Gibt LC_INVALID zurueck wenn das Format nicht erkannt wird. */
static license_class_t decode_license_class(const char *in, int len) {
    if (len < 2) return LC_INVALID;
    uint8_t head = (uint8_t)in[0];
    uint8_t tail = (uint8_t)in[len - 1];
    uint8_t cls  = mba_xor(head, tail);
    cls = mba_add(cls, (uint8_t)len);
    /* Klassen-Mapping via obere Nibbles */
    switch (cls >> 4) {
        case 0x4: case 0x5: return LC_TRIAL;
        case 0x6: case 0x7: return LC_STANDARD;
        case 0x8: case 0x9: return LC_EXTENDED;
        case 0xA: case 0xB: return LC_ENTERPRISE;
        default:             return LC_INVALID;
    }
}

/* Gibt Mindest-Laenge fuer eine Lizenzklasse zurueck */
static int lc_min_length(license_class_t cls) {
    switch (cls) {
        case LC_TRIAL:      return 12;
        case LC_STANDARD:   return 16;
        case LC_EXTENDED:   return 19;
        case LC_ENTERPRISE: return 19;
        default:            return 0;
    }
}

/* ------------------------------------------------------------------ */
/* [CSPLIT] Konstanten zusammenbauen                                   */
/* ------------------------------------------------------------------ */
static uint32_t fold_const(const uint8_t parts[4]) {
    uint32_t v = 0;
    for (int i = 0; i < 4; i++) v = (v << 8) | parts[CS_PERM[i]];
    return v;
}

/* ------------------------------------------------------------------ */
/* S-Box (wie v2)                                                      */
/* ------------------------------------------------------------------ */
static void mk(void) {
    for (int i = 0; i < 256; i++) T[i] = (uint8_t)((i * 167 + 13) & 0xFF);
    uint8_t k = 0x5A;
    for (int i = 0; i < 256; i++) {
        k = (uint8_t)(k + T[i] + i);
        uint8_t tmp = T[i]; T[i] = T[k]; T[k] = tmp;
    }
    g_t = 1;
}
static void mki(uint8_t *iv) {
    if (!g_t) mk();
    for (int i = 0; i < 256; i++) iv[T[i]] = (uint8_t)i;
}

/* ------------------------------------------------------------------ */
/* Zustandsinitialisierung                                             */
/* ------------------------------------------------------------------ */
static void init_state(void) {
    uint32_t a_hi = fold_const(CS_A);
    uint32_t b_hi = fold_const(CS_B);
    if (op_always_true(42)) { g_a = a_hi; g_b = b_hi; }
    else                    { g_a = ~a_hi; g_b = ~b_hi; }
}

/* ------------------------------------------------------------------ */
/* f0: Hilfswert fuer Stage5 (wie v2)                                 */
/* ------------------------------------------------------------------ */
static uint8_t f0(void) {
    uint8_t s = 0;
    for (int i = 0; i < 16; i++) { s = mba_xor(s, A0[i]); s = rl(s, 3); }
    return s;
}

/* ------------------------------------------------------------------ */
/* [AD] Anti-Debugging                                                 */
/* ------------------------------------------------------------------ */
static uint8_t debugger_skew(void) {
#if defined(__linux__)
    long r = syscall(SYS_ptrace, 0, 0, 0, 0);
    if (r == -1) return 0x6B;
    syscall(SYS_ptrace, 17, 0, 0, 0);
    return 0x00;
#elif defined(__APPLE__)
    int r = ptrace(PT_DENY_ATTACH, 0, 0, 0);
    if (r == -1) return 0x6B;
    return 0x00;
#else
    return 0x00;
#endif
}

/* [TCTRL] Timing-Skew: misst Nanosekunden pro Iteration; unter
 * Einzelschritt (gdb/lldb) ist der Wert viel groesser als 50000 ns.
 * Das Ergebnis fliesst als zweiter Skew in die Pruefung ein. */
static uint8_t timing_skew(void) {
    struct timespec t0, t1;
    volatile uint64_t acc = 0;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    for (volatile int i = 0; i < 1000; i++) acc += (uint64_t)i;
    clock_gettime(CLOCK_MONOTONIC, &t1);
    (void)acc;
    uint64_t ns = (uint64_t)(t1.tv_sec - t0.tv_sec) * 1000000000ULL
                + (uint64_t)(t1.tv_nsec - t0.tv_nsec);
    return (ns > 50000ULL) ? 0x37 : 0x00;
}

/* ------------------------------------------------------------------ */
/* [VM] Mini-Bytecode-Interpreter (wie v2, unveraendert)              */
/* ------------------------------------------------------------------ */
enum { OP_LOADX=1, OP_ROR_PV=2, OP_XOR_PV=3, OP_SUB_S=4, OP_STORE=5, OP_HALT=0 };
static const uint8_t VM_PROG[] = { OP_LOADX, OP_ROR_PV, OP_XOR_PV, OP_SUB_S, OP_STORE, OP_HALT };

static void vm_run_stage5(uint8_t *b, int n, uint8_t s) {
    uint8_t pv = s;
    for (int i = 0; i < n; i++) {
        uint8_t x = 0, cur = 0;
        int pc = 0, running = 1;
        while (running) {
            switch (VM_PROG[pc++]) {
                case OP_LOADX:  x = b[i]; cur = x; break;
                case OP_ROR_PV: x = rr(x, pv & 7); break;
                case OP_XOR_PV: x = mba_xor(x, pv); break;
                case OP_SUB_S:  x = mba_sub(x, s); break;
                case OP_STORE:  b[i] = x; pv = cur; break;
                case OP_HALT: default: running = 0; break;
            }
        }
    }
}

/* ------------------------------------------------------------------ */
/* [CFF] + [IND]: fuenf Stufen ueber Dispatcher + maskierte Pointer   */
/* ------------------------------------------------------------------ */
enum { ST_INIT=0, ST_S1, ST_S2, ST_S3, ST_S4, ST_S5, ST_DONE };

typedef void (*stage_fn)(uint8_t *, int, uint8_t *);

static void stage1_lcg(uint8_t *b, int n, uint8_t *iv) {
    (void)iv;
    uint32_t s = g_b;
    for (int i = 0; i < n; i++) {
        s = s * 1103515245u + 12345u;
        b[i] = mba_xor(b[i], (uint8_t)(s >> 24));
    }
}
static void stage2_shift(uint8_t *b, int n, uint8_t *iv) {
    (void)iv;
    uint32_t c = g_a;
    for (int i = 0; i < n; i++) {
        b[i] = mba_sub(b[i], (uint8_t)(c & 0xFF));
        c = (c >> 8) | (c << 24);
    }
}
static void stage3_acc(uint8_t *b, int n, uint8_t *iv) {
    (void)iv;
    uint8_t acc = 0x3C;
    for (int i = 0; i < n; i++) {
        uint8_t c = b[i];
        b[i] = mba_xor(c, acc);
        acc = (uint8_t)(acc * 33 + c);
    }
}
static void stage4_inv(uint8_t *b, int n, uint8_t *iv) {
    uint8_t pv = 0xA5;
    for (int i = 0; i < n; i++) {
        uint8_t y = b[i];
        b[i] = mba_sub(iv[y], pv);
        pv = y;
    }
}
static void stage5_vm(uint8_t *b, int n, uint8_t *iv) {
    (void)iv;
    vm_run_stage5(b, n, f0());
}

static uintptr_t mask_ptr(stage_fn f, uintptr_t key) { return ((uintptr_t)f) ^ key; }
static stage_fn  unmask_ptr(uintptr_t m, uintptr_t key) { return (stage_fn)(m ^ key); }

/* Transformiert einen Puffer durch alle fuenf Stufen (v2-Logik). */
static void reveal(uint8_t *b, int n) {
    if (!g_t) mk();
    uint8_t iv[256];
    mki(iv);

    uintptr_t pk = (uintptr_t)(g_a ^ g_b ^ 0xA5A5A5A5u);
    uintptr_t table[4] = {
        mask_ptr(stage1_lcg,   pk),
        mask_ptr(stage2_shift, pk),
        mask_ptr(stage3_acc,   pk),
        mask_ptr(stage4_inv,   pk),
    };

    int state = ST_INIT, step = 0;
    while (state != ST_DONE) {
        /* [JUNK] */
        volatile uint32_t noise = (uint32_t)state * 2654435761u;
        noise ^= (noise >> 13); (void)noise;

        switch (state) {
            case ST_INIT:
                state = op_always_true(step) ? ST_S1 : ST_DONE;
                break;
            case ST_S1: { stage_fn f = unmask_ptr(table[0], pk); f(b, n, iv); state = ST_S2; break; }
            case ST_S2: { stage_fn f = unmask_ptr(table[1], pk); f(b, n, iv); state = ST_S3; break; }
            case ST_S3: { stage_fn f = unmask_ptr(table[2], pk); f(b, n, iv); state = ST_S4; break; }
            case ST_S4: { stage_fn f = unmask_ptr(table[3], pk); f(b, n, iv); state = ST_S5; break; }
            case ST_S5: stage5_vm(b, n, iv); state = ST_DONE; break;
            default:    state = ST_DONE; break;
        }
        step++;
    }
}

/* ------------------------------------------------------------------ */
/* [INPUT] + [NODUMP]: Pro-Byte-Sollwert mit Verkettung               */
/* ------------------------------------------------------------------ */
/*
 * target_byte liefert das erwartete Eingabe-Byte an Position i.
 * Es haengt ab von: A1[i] (nach reveal-Transformation), seedb, prev
 * (Verkettung mit Vorgaenger), ad_skew (ptrace) und t_skew (Timing).
 * Der Sollwert existiert nur fuer die Dauer eines Schleifendurchlaufs.
 */
static uint8_t target_byte(uint8_t revealed_i, int i,
                            uint8_t seedb, uint8_t prev,
                            uint8_t ad_skew, uint8_t t_skew) {
    uint8_t t = revealed_i;
    t = mba_xor(t, seedb);
    t = mba_add(t, (uint8_t)(i * 7));
    t = mba_xor(t, prev);
    t = mba_add(t, ad_skew);
    t = mba_add(t, t_skew);
    return t;
}

/* ------------------------------------------------------------------ */
/* main                                                                */
/* ------------------------------------------------------------------ */
int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr, "usage: %s <license-key>\n", argv[0]);
        return 1;
    }
    init_state();

    const char *in = argv[1];
    int inlen = (int)strlen(in);

    /* Vorfilter: Format- und Zeichensatzpruefung */
    if (!lc_precheck(in, inlen)) {
        printf("Access denied.\n");
        return 1;
    }

    /* Lizenzklasse bestimmen */
    license_class_t lcls = decode_license_class(in, inlen);
    if (lc_min_length(lcls) > inlen) {
        printf("Access denied.\n");
        return 1;
    }

    /* [AD] Skews einmalig bestimmen */
    uint8_t ad_skew = debugger_skew();
    uint8_t t_skew  = timing_skew();

    /* Seed aus CSPLIT */
    uint32_t seed = fold_const(CS_SEED);

    uint8_t rbuf[KEYLEN];
    for (int i = 0; i < KEYLEN; i++) rbuf[i] = A1[i];
    reveal(rbuf, KEYLEN);

    /* Integritaet der Transformationskette pruefen */
    if (!verify_integrity(rbuf, KEYLEN)) {
        printf("Access denied.\n");
        return 1;
    }

    /* [HASH] FNV-1a-Akkumulator statt direktem Byte-Vergleich */
    uint32_t h_got  = 2166136261u;
    uint32_t h_want = 2166136261u;

    int len_ok = (inlen == KEYLEN);
    uint8_t prev = 0x2A;

    for (int i = 0; i < KEYLEN; i++) {
        uint8_t seedb = op_always_true(i)
                        ? (uint8_t)(seed >> ((i & 3) * 8))
                        : 0;

        uint8_t t = target_byte(rbuf[i], i, seedb, prev, ad_skew, t_skew);

        uint8_t inb = (len_ok && i < inlen) ? (uint8_t)in[i] : 0xFF;

        h_got  = (h_got  ^ inb) * 16777619u;
        h_want = (h_want ^ t)   * 16777619u;

        prev = t;
        volatile uint8_t wipe = (uint8_t)(t ^ 0xFF);
        t = wipe; (void)t;
    }

    volatile uint8_t *vp = rbuf;
    for (int i = 0; i < KEYLEN; i++) vp[i] = 0;

    /* Lizenzklassen-abhaengige Zusatzpruefung */
    volatile uint32_t cls_check = (uint32_t)lcls * 0x9E3779B9u;
    cls_check ^= (cls_check >> 16);
    (void)cls_check;

    int ok = len_ok && (h_got == h_want);

    if (ok) printf("Access granted. Welcome, licensed user.\n");
    else    printf("Access denied.\n");

    volatile uint32_t dummy = h_got ^ h_want ^ 0xDEADBEEFu;
    (void)dummy;

    return ok ? 0 : 1;
}
