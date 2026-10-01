/*
 * lv.c -- "LicenseGuard" (stark gehaertete Fassung, v2)
 *
 * Aufruf:  ./lv <lizenzschluessel>
 *
 * Funktional IDENTISCH zur unverschleierten Referenzversion: derselbe
 * Lizenzschluessel wird akzeptiert. Nur die *Lesbarkeit* fuer einen
 * Analysten wurde massiv reduziert.
 *
 * Eingesetzte Obfuskationstechniken (siehe Kommentare im Code):
 *
 *   [CFF]  Control-Flow-Flattening   - die eigentliche Ablauflogik steckt
 *          in einer einzigen Dispatch-Schleife ueber einen Zustands-
 *          automaten (ein "switch" statt sichtbarer if/for-Struktur).
 *          Der native Kontrollfluss (Caller/Callee-Beziehung, Schleifen-
 *          grenzen) ist dadurch im Disassembler nicht mehr direkt an der
 *          Funktionsgrenze erkennbar.
 *
 *   [OP]   Opaque Predicates          - Bedingungen, die sich wie eine
 *          echte Fallunterscheidung lesen, aber algebraisch IMMER zu
 *          einem festen Wert auswerten (z.B. (x*x - (x-1)*(x+1)) == 1
 *          fuer jedes ganzzahlige x). Ein Analyst muss das erst beweisen,
 *          bevor er den toten Zweig verwerfen darf.
 *
 *   [MBA]  Mixed Boolean-Arithmetic   - arithmetische/boolesche Mini-
 *          Ausdruecke, die dieselbe Operation (z.B. XOR, ADD) durch eine
 *          aequivalente, aber unuebersichtliche Bitformel ersetzen
 *          (z.B. a^b == (a|b) - (a&b)).
 *
 *   [IND]  Indirekte Aufrufe          - die eigentlichen Transformations-
 *          stufen werden nicht direkt aufgerufen, sondern ueber eine zur
 *          Laufzeit aus mehreren XOR-Teilen zusammengesetzte Funktions-
 *          zeigertabelle angesprungen.
 *
 *   [CSPLIT] Konstanten-Splitting     - Konstanten liegen nicht mehr als
 *          ein Literal im Code, sondern als mehrere Teile, die erst zur
 *          Laufzeit per XOR/Rotation rekombiniert werden.
 *
 *   [VM]   Mini-Bytecode-Interpreter  - die letzte Transformationsstufe
 *          wird nicht mehr als C-Schleife ausgedrueckt, sondern als
 *          kleines Bytecode-Programm, das von einer generischen VM-
 *          Schleife interpretiert wird. Im Disassembler sieht man nur
 *          einen Interpreter-Dispatcher, nicht die eigentliche Operation.
 *
 *   [JUNK] Dead Code                  - Berechnungen, deren Ergebnis nie
 *          verwendet wird, aber wie sicherheitsrelevanter Code aussehen
 *          (z.B. eine zweite, ungenutzte "Pruefsumme").
 *
 * WICHTIG fuer die Uebung: Jede dieser Techniken ist invertierbar bzw.
 * mit genug Geduld symbolisch/durch Emulation aufloesbar -- echte
 * Sicherheit entsteht daraus nicht, nur ein hoeherer Analyseaufwand.
 */
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

/* ------------------------------------------------------------------ */
/* Rohdaten (weiterhin in .rodata)                                     */
/* ------------------------------------------------------------------ */
static const uint8_t A0[16] = {
    0x9E,0x37,0x79,0xB9,0x7F,0x4A,0x7C,0x15,
    0xF3,0x9C,0xC0,0x60,0x51,0x2D,0xA3,0x1B
};
static const uint8_t A1[19] = {
    0x84,0xC3,0x37,0x2E,0x43,0x88,0x10,0x41,0x76,0xB4,
    0x14,0xE6,0x62,0x16,0xC4,0xA4,0x39,0x32,0xF3
};

/* [CSPLIT] P0 liegt nicht mehr direkt vor: jede 32-bit-Konstante ist in
 * vier 8-bit-Scherben zerlegt, die ueber einen kleinen Permutations-
 * index wieder zusammengesetzt werden. 0xC0DE1337 und 0x1337C0DE sind
 * so nirgends als zusammenhaengendes Literal im Binary zu finden. */
static const uint8_t CS_A[4] = { 0xC0, 0xDE, 0x13, 0x37 };
static const uint8_t CS_B[4] = { 0x13, 0x37, 0xC0, 0xDE };
static const uint8_t CS_PERM[4] = { 0, 1, 2, 3 }; /* zur Laufzeit "berechnet" */

static uint8_t T[256];
static uint8_t g_t = 0;
static uint32_t g_a = 0, g_b = 0;

/* ------------------------------------------------------------------ */
/* [OP] Opaque-Predicate-Helfer                                        */
/* ------------------------------------------------------------------ */
/* Wertet FUER JEDES x zu 1 aus: x*x - (x-1)*(x+1) == 1.
 * Sieht wie eine datenabhaengige Bedingung aus, ist aber eine
 * Identitaet und daher niemals falsch. */
static int op_always_true(int x) {
    return (x * x - (x - 1) * (x + 1)) == 1;
}

/* Wertet FUER JEDES x zu 0 aus: (x | ~x) + 1 == 0 (mod 2^32). */
static int op_always_false(unsigned x) __attribute__((unused));
static int op_always_false(unsigned x) {
    return (int)((x | ~x) + 1u) != 0 ? 0 : 0; /* strukturell immer 0 */
}

/* ------------------------------------------------------------------ */
/* [MBA] Mixed-Boolean-Arithmetic-Ersatz fuer XOR/ADD/SUB auf uint8_t   */
/* ------------------------------------------------------------------ */
static uint8_t mba_xor(uint8_t a, uint8_t b) {
    /* a ^ b  ==  (a | b) - (a & b) */
    return (uint8_t)((a | b) - (a & b));
}
static uint8_t mba_add(uint8_t a, uint8_t b) {
    /* a + b  ==  (a ^ b) + 2*(a & b)   (klassische Halbaddierer-Identitaet) */
    return (uint8_t)((a ^ b) + ((a & b) << 1));
}
static uint8_t mba_sub(uint8_t a, uint8_t b) {
    /* a - b  ==  a + (~b) + 1 */
    return (uint8_t)(a + (uint8_t)(~b) + 1);
}

static uint8_t rr(uint8_t v, int r) {
    r &= 7;
    /* MBA-verschleierte Rotation: Ersetzt den direkten Shift/Or durch
     * eine Maskierung ueber eine Differenz statt eines einfachen OR. */
    uint8_t hi = (uint8_t)(v >> r);
    uint8_t lo = (uint8_t)(v << (8 - r));
    return mba_add(hi, lo); /* kein Ueberlapp der Bits -> ADD == OR hier */
}
static uint8_t rl(uint8_t v, int r) {
    r &= 7;
    uint8_t hi = (uint8_t)(v << r);
    uint8_t lo = (uint8_t)(v >> (8 - r));
    return mba_add(hi, lo);
}

static uint8_t f0(void) {
    uint8_t s = 0;
    for (int i = 0; i < 16; i++) {
        s = mba_xor(s, A0[i]);
        s = rl(s, 3);
    }
    return s;
}

static void mk(void) {
    for (int i = 0; i < 256; i++) T[i] = (uint8_t)((i * 167 + 13) & 0xFF);
    uint8_t k = 0x5A;
    for (int i = 0; i < 256; i++) {
        k = (uint8_t)(k + T[i] + i);
        uint8_t t = T[i];
        T[i] = T[k];
        T[k] = t;
    }
    g_t = 1;
}
static void mki(uint8_t *iv) {
    if (!g_t) mk();
    for (int i = 0; i < 256; i++) iv[T[i]] = (uint8_t)i;
}

/* [CSPLIT] Konstanten erst zur Laufzeit aus den Scherben zusammenbauen. */
static uint32_t fold_const(const uint8_t parts[4]) {
    uint32_t v = 0;
    for (int i = 0; i < 4; i++) {
        int idx = CS_PERM[i]; /* Identitaets-Permutation, aber zur
                                  Laufzeit berechnet, nicht konstant */
        v = (v << 8) | parts[idx];
    }
    return v;
}

static void init_state(void) {
    uint32_t a_hi = fold_const(CS_A);          /* 0xC0DE1337 */
    uint32_t b_hi = fold_const(CS_B);          /* 0x1337C0DE */
    /* [OP] eine immer-wahre Bedingung, die wie eine Laufzeitpruefung
     * aussieht, aber nie den Wert veraendert. */
    if (op_always_true(42)) {
        g_a = a_hi;
        g_b = b_hi;
    } else {
        /* toter Zweig, wird nie ausgefuehrt */
        g_a = ~a_hi;
        g_b = ~b_hi;
    }
}

/* ------------------------------------------------------------------ */
/* [VM] Mini-Bytecode-Interpreter fuer die letzte Transformationsstufe  */
/* ------------------------------------------------------------------ */
/* Opcodes sind absichtlich nichtssagend benannt. */
enum { OP_LOADX = 1, OP_ROR_PV = 2, OP_XOR_PV = 3, OP_SUB_S = 4, OP_STORE = 5, OP_HALT = 0 };

/* Programm fuer EIN Byte der letzten Stufe:
 *   x = b[i]
 *   x = ror(x, pv & 7)
 *   x = x ^ pv
 *   x = x - s
 *   b[i] = x
 */
static const uint8_t VM_PROG[] = {
    OP_LOADX, OP_ROR_PV, OP_XOR_PV, OP_SUB_S, OP_STORE, OP_HALT
};

static void vm_run_stage5(uint8_t *b, int n, uint8_t s) {
    uint8_t pv = s;
    for (int i = 0; i < n; i++) {
        uint8_t x = 0, cur = 0;
        int pc = 0;
        int running = 1;
        while (running) {
            uint8_t op = VM_PROG[pc++];
            switch (op) {
                case OP_LOADX:
                    x = b[i];
                    cur = x;
                    break;
                case OP_ROR_PV:
                    x = rr(x, pv & 7);
                    break;
                case OP_XOR_PV:
                    x = mba_xor(x, pv);
                    break;
                case OP_SUB_S:
                    x = mba_sub(x, s);
                    break;
                case OP_STORE:
                    b[i] = x;
                    pv = cur;
                    break;
                case OP_HALT:
                default:
                    running = 0;
                    break;
            }
        }
    }
}

/* ------------------------------------------------------------------ */
/* [CFF] Control-Flow-Flattening: alle fuenf Stufen von reveal() laufen */
/* als Zustaende eines einzigen Dispatchers statt als sichtbare Folge   */
/* separater Funktionsaufrufe/Schleifen.                                */
/* ------------------------------------------------------------------ */
enum {
    ST_INIT = 0,
    ST_STAGE1_LCG,
    ST_STAGE2_SHIFT,
    ST_STAGE3_ACC,
    ST_STAGE4_INV,
    ST_STAGE5_VM,
    ST_DONE
};

/* [IND] Stage-Funktionen, die ueber eine zur Laufzeit entschluesselte
 * Zeigertabelle angesprungen werden, statt direkt aufgerufen zu werden. */
typedef void (*stage_fn)(uint8_t *b, int n, uint8_t *iv);

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
        uint8_t kb = (uint8_t)(c & 0xFF);
        b[i] = mba_sub(b[i], kb);
        c = (c >> 8) | (c << 24);
    }
}
static void stage3_acc(uint8_t *b, int n, uint8_t *iv) {
    (void)iv;
    uint8_t acc = 0x3C;
    for (int i = 0; i < n; i++) {
        uint8_t c = b[i];
        uint8_t p = mba_xor(c, acc);
        acc = (uint8_t)(acc * 33 + c);
        b[i] = p;
    }
}
static void stage4_inv(uint8_t *b, int n, uint8_t *iv) {
    uint8_t pv = 0xA5;
    for (int i = 0; i < n; i++) {
        uint8_t y = b[i];
        uint8_t ix = iv[y];
        b[i] = mba_sub(ix, pv);
        pv = y;
    }
}
static void stage5_vm(uint8_t *b, int n, uint8_t *iv) {
    (void)iv;
    vm_run_stage5(b, n, f0());
}

/* [IND] Die vier "echten" Pointer werden mit einem Laufzeit-Schluessel
 * XOR-maskiert abgelegt und erst im Dispatcher unmaskiert. Ein
 * statischer Disassembler sieht in der Tabelle nur sinnlos aussehende
 * Adressen. (uintptr_t-Arithmetik auf Funktionspointern ist technisch
 * implementation-defined, aber auf allen gaengigen ELF/Mach-O-Targets
 * unproblematisch und fuer Obfuskations-Uebungszwecke ueblich.) */
static uintptr_t mask_ptr(stage_fn f, uintptr_t key) {
    return ((uintptr_t)f) ^ key;
}
static stage_fn unmask_ptr(uintptr_t masked, uintptr_t key) {
    return (stage_fn)(masked ^ key);
}

static void reveal(uint8_t *b, int n) {
    if (!g_t) mk();
    uint8_t iv[256];
    mki(iv);

    /* Laufzeit-"Schluessel" fuer die Pointer-Maskierung -- bewusst aus
     * einer Laufzeitberechnung statt eines Literals gewonnen. */
    uintptr_t pk = (uintptr_t)(g_a ^ g_b ^ 0xA5A5A5A5u);

    uintptr_t table[4] = {
        mask_ptr(stage1_lcg, pk),
        mask_ptr(stage2_shift, pk),
        mask_ptr(stage3_acc, pk),
        mask_ptr(stage4_inv, pk),
    };

    int state = ST_INIT;
    int step = 0; /* Index in table[] fuer die indirekten Stufen */

    /* [CFF] Dispatcher-Schleife statt sichtbarer linearer Abfolge. */
    while (state != ST_DONE) {
        /* [JUNK] totes Pruefsummen-Geschnoerkel, dessen Ergebnis nie
         * benutzt wird -- lenkt vom eigentlichen Dispatch-Wert ab. */
        volatile uint32_t noise = (uint32_t)state * 2654435761u;
        noise ^= (noise >> 13);
        (void)noise;

        switch (state) {
            case ST_INIT:
                /* [OP] weitere immer-wahre Bedingung als Scheinverzweigung */
                state = op_always_true(step) ? ST_STAGE1_LCG : ST_DONE;
                break;

            case ST_STAGE1_LCG: {
                stage_fn f = unmask_ptr(table[0], pk);
                f(b, n, iv);
                state = ST_STAGE2_SHIFT;
                break;
            }
            case ST_STAGE2_SHIFT: {
                stage_fn f = unmask_ptr(table[1], pk);
                f(b, n, iv);
                state = ST_STAGE3_ACC;
                break;
            }
            case ST_STAGE3_ACC: {
                stage_fn f = unmask_ptr(table[2], pk);
                f(b, n, iv);
                state = ST_STAGE4_INV;
                break;
            }
            case ST_STAGE4_INV: {
                stage_fn f = unmask_ptr(table[3], pk);
                f(b, n, iv);
                state = ST_STAGE5_VM;
                break;
            }
            case ST_STAGE5_VM:
                stage5_vm(b, n, iv);
                state = ST_DONE;
                break;

            default:
                state = ST_DONE;
                break;
        }
        step++;
    }
}

/* ------------------------------------------------------------------ */
/* Konstante-Zeit-Vergleich (unveraendert, bis auf MBA-XOR)            */
/* ------------------------------------------------------------------ */
static int eq_ct(const uint8_t *a, const uint8_t *b, int n) {
    uint8_t d = 0;
    for (int i = 0; i < n; i++) d = mba_xor(d, mba_xor(a[i], b[i]));
    return d == 0;
}

int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr, "usage: %s <license-key>\n", argv[0]);
        return 1;
    }
    init_state();

    uint8_t key[19];
    for (int i = 0; i < 19; i++) key[i] = A1[i];
    reveal(key, 19);

    const char *in = argv[1];
    int ok = (strlen(in) == 19) && eq_ct((const uint8_t *)in, key, 19);

    if (ok) printf("Access granted. Welcome, licensed user.\n");
    else    printf("Access denied.\n");

    volatile uint8_t z = 0;
    for (int i = 0; i < 19; i++) z = mba_xor(z, key[i]);
    (void)z;
    return ok ? 0 : 1;
}