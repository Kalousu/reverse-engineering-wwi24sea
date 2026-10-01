/*
 * lv.c -- "LicenseGuard" v3 (konzeptionell gehaertet)
 *
 * Aufruf:  ./lv <lizenzschluessel>
 *
 * UNTERSCHIED ZU v1/v2 -- das ist der eigentliche Fix:
 *
 *   Fruehere Versionen haben den gueltigen Schluessel zur Laufzeit im
 *   RAM REKONSTRUIERT und dann byteweise verglichen (reveal()+eq_ct()).
 *   Dadurch MUSSTE der Klartext-Schluessel irgendwann im Speicher
 *   stehen -- und war per Debugger (Breakpoint nach reveal(), Memory-
 *   Dump) trivial auslesbar. Saemtliche Obfuskierung (CFF, MBA, VM, ...)
 *   hat das nicht verhindert, weil sie nur den WEG zur Rekonstruktion
 *   verschleiert, nicht die Tatsache der Rekonstruktion.
 *
 *   v3 dreht die Richtung um:
 *     - Es gibt KEINEN gespeicherten Klartext-Schluessel mehr.
 *     - Die Nutzereingabe wird gehasht (Einwegfunktion) und der Hash
 *       gegen einen fest eingebauten Soll-Hash geprueft.
 *     - Hashen ist nicht umkehrbar -> aus dem, was im RAM liegt
 *       (Soll-Hash + Hash der Eingabe), laesst sich der gueltige
 *       Schluessel NICHT zurueckrechnen.
 *
 * GRENZEN (ehrlich, gehoeren in die Doku):
 *   1) Der Entscheidungs-Branch ("ok") ist weiterhin patchbar
 *      (je->jmp) -> "granted" ohne Schluessel. Hash-Verify verhindert
 *      das AUSLESEN des Schluessels, nicht das UMGEHEN der Pruefung.
 *      Vollstaendige Abwehr: Schluessel eine echte Decrypt-Key ableiten
 *      lassen (AEAD), sodass es ohne korrekten Schluessel keine
 *      Funktionalitaet und keinen Branch zum Patchen gibt.
 *   2) Der selbstgebaute Hash hier ist NUR fuer die Uebung. In
 *      Produktion: Argon2id/scrypt/bcrypt mit zufaelligem Salt pro
 *      Lizenz (speicher-hart gegen GPU-Brute-Force).
 *   3) Brute-Force bleibt moeglich, wenn der Schlusselraum klein ist.
 *      Deshalb: hohe Rundenzahl (langsam) + ausreichende Schluessel-
 *      entropie.
 */
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

/* Salt muss nicht geheim sein (darf im Binary stehen). Zweck: gleiche
 * Schluessel ergeben bei unterschiedlichem Salt unterschiedliche Hashes
 * -> keine Rainbow-Tables, kein Teilen vorberechneter Tabellen. */
static const uint8_t SALT[16] = {
    0x7a,0x1c,0x44,0x90,0xe3,0x55,0x02,0xab,
    0x6f,0x18,0xcc,0x21,0x9d,0x40,0xb7,0x8e
};

static const uint8_t STORED_HASH[32] = {
    0x8F,0x1F,0x0A,0x94,0xAC,0xE1,0xC0,0x79,
    0xF3,0x50,0x71,0x35,0x46,0xFF,0x7E,0xAE,
    0x0F,0x60,0xB0,0xD9,0xC6,0xF6,0x4A,0xDB,
    0x1B,0x4F,0x29,0x35,0x2C,0xDC,0x8E,0xC9
};

/* Einweg-Hash (iteriert, absichtlich langsam). IDENTISCH zu genhash.c. */
static void lg_hash(const uint8_t *salt, int slen,
                    const uint8_t *in, int ilen,
                    uint8_t out[32]) {
    uint32_t h[8] = {
        0x6a09e667u,0xbb67ae85u,0x3c6ef372u,0xa54ff53au,
        0x510e527fu,0x9b05688cu,0x1f83d9abu,0x5be0cd19u
    };
    uint8_t buf[512];
    int n = 0;
    for (int i = 0; i < slen && n < (int)sizeof(buf); i++) buf[n++] = salt[i];
    for (int i = 0; i < ilen && n < (int)sizeof(buf); i++) buf[n++] = in[i];

    for (int round = 0; round < 3000000; round++) {
        for (int i = 0; i < n; i++) {
            uint32_t k = (uint32_t)buf[i] + (uint32_t)i * 2654435761u + (uint32_t)round;
            int j = i & 7;
            h[j] ^= k;
            h[j] = (h[j] << 7) | (h[j] >> 25);
            h[j] += h[(j+1)&7];
            h[(j+1)&7] ^= (h[j] >> 11);
            h[(j+2)&7] += h[j];
        }
        for (int j = 0; j < 8; j++) {
            h[j] += h[(j+3)&7] ^ (h[(j+5)&7] << 3);
            h[j] = (h[j] << 13) | (h[j] >> 19);
        }
    }
    for (int j = 0; j < 8; j++) {
        out[j*4+0] = (uint8_t)(h[j]      );
        out[j*4+1] = (uint8_t)(h[j] >>  8);
        out[j*4+2] = (uint8_t)(h[j] >> 16);
        out[j*4+3] = (uint8_t)(h[j] >> 24);
    }
}

/* Konstante-Zeit-Vergleich: verhindert, dass ein Angreifer per
 * Laufzeit-Seitenkanal Byte fuer Byte des Soll-Hashes errechnet.
 * (Beim Hash-Vergleich weniger kritisch als beim Klartext, aber gute
 * Praxis.) */
static int ct_eq(const uint8_t *a, const uint8_t *b, int n) {
    uint8_t d = 0;
    for (int i = 0; i < n; i++) d |= (uint8_t)(a[i] ^ b[i]);
    return d == 0;
}

int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr, "usage: %s <license-key>\n", argv[0]);
        return 1;
    }

    const char *in = argv[1];

    /* Eingabe hashen -- im RAM liegt nur der Hash der EINGABE und der
     * Soll-Hash, NIE der gueltige Klartext-Schluessel. */
    uint8_t h[32];
    lg_hash(SALT, 16, (const uint8_t *)in, (int)strlen(in), h);

    int ok = ct_eq(h, STORED_HASH, 32);

    if (ok) printf("Access granted. Welcome, licensed user.\n");
    else    printf("Access denied.\n");

    return ok ? 0 : 1;
}
