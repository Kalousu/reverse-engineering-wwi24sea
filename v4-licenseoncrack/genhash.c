/* genhash.c -- erzeugt den Soll-Hash fuer einen gegebenen Lizenzschluessel.
 * Einmalig ausfuehren, Ausgabe in lv.c (STORED_HASH) uebernehmen.
 *
 * Hinweis: Dies ist ein selbstgebauter iterierter Hash NUR fuer die
 * Uebung (keine externen Abhaengigkeiten). Fuer echten Einsatz:
 * Argon2id / scrypt / bcrypt mit zufaelligem Salt pro Lizenz.
 */
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

/* 32-Byte Hash ueber eine simple, aber nichttriviale Kompressions-
 * schleife (ARX-artig). Bewusst mit vielen Runden, um Brute-Force
 * zu verteuern. Salt wird vorangestellt. */
static void lg_hash(const uint8_t *salt, int slen,
                    const uint8_t *in, int ilen,
                    uint8_t out[32]) {
    uint32_t h[8] = {
        0x6a09e667u,0xbb67ae85u,0x3c6ef372u,0xa54ff53au,
        0x510e527fu,0x9b05688cu,0x1f83d9abu,0x5be0cd19u
    };
    /* salt || input zusammenfuehren */
    uint8_t buf[512];
    int n = 0;
    for (int i = 0; i < slen && n < (int)sizeof(buf); i++) buf[n++] = salt[i];
    for (int i = 0; i < ilen && n < (int)sizeof(buf); i++) buf[n++] = in[i];

    /* viele Runden -> absichtlich langsam */
    for (int round = 0; round < 3000000; round++) {
        for (int i = 0; i < n; i++) {
            uint32_t k = (uint32_t)buf[i] + (uint32_t)i * 2654435761u + (uint32_t)round;
            int j = i & 7;
            h[j] ^= k;
            h[j] = (h[j] << 7) | (h[j] >> 25);     /* rotl 7 */
            h[j] += h[(j+1)&7];
            h[(j+1)&7] ^= (h[j] >> 11);
            h[(j+2)&7] += h[j];
        }
        /* Quermischung zwischen den Woertern */
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

int main(int argc, char **argv) {
    if (argc != 2) { fprintf(stderr, "usage: %s <key>\n", argv[0]); return 1; }
    /* Fester Salt fuer die Uebung (in Produktion: zufaellig & pro Lizenz).
     * Auch im Binary sichtbar -- das ist OK, Salt muss nicht geheim sein. */
    static const uint8_t SALT[16] = {
        0x7a,0x1c,0x44,0x90,0xe3,0x55,0x02,0xab,
        0x6f,0x18,0xcc,0x21,0x9d,0x40,0xb7,0x8e
    };
    uint8_t out[32];
    lg_hash(SALT, 16, (const uint8_t*)argv[1], (int)strlen(argv[1]), out);

    printf("/* Hash fuer Schluessel \"%s\" */\n", argv[1]);
    printf("static const uint8_t STORED_HASH[32] = {\n    ");
    for (int i = 0; i < 32; i++) {
        printf("0x%02X%s", out[i], i==31?"":(i%8==7?",\n    ":","));
    }
    printf("\n};\n");
    return 0;
}
