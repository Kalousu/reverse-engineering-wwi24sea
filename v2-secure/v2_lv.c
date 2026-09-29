/*
 * lv.c -- "License Validator" (gehärtete Fassung)
 *
 * Verhalten identisch zur ungehärteten Version:
 *   ./lv <password>   -> "Access denied." / "Access granted. ..."
 * Flag liegt verschlüsselt in .rodata, unabhängig vom Passwort entschlüsselbar.
 *
 * Härtung (ändert NICHT den Algorithmus, nur die Lesbarkeit):
 *  - Rundenkonstanten werden zur Laufzeit aus mehreren Quellen gefaltet
 *    (keine sprechenden Literale; Werte tauchen statisch nicht auf).
 *  - Zustand ist über Globals + separate Init verteilt.
 *  - Nichtssagende Bezeichner; Runden teils verschränkt.
 */
#include <stdint.h>
#include <stdio.h>
#include <string.h>

/* rohdaten-bloecke (in .rodata; zweck nicht offensichtlich) */
static const uint8_t A0[16]={0x9E,0x37,0x79,0xB9,0x7F,0x4A,0x7C,0x15,0xF3,0x9C,0xC0,0x60,0x51,0x2D,0xA3,0x1B};
static const uint8_t A1[19]={0x84,0xC3,0x37,0x2E,0x43,0x88,0x10,0x41,0x76,0xB4,0x14,0xE6,0x62,0x16,0xC4,0xA4,0x39,0x32,0xF3};
/* konstanten in teile zerlegt -> zur laufzeit rekombiniert */
static const uint32_t P0[4]={0xC0DE0000u,0x00001337u,0x13370000u,0x0000C0DEu};

static uint8_t T[256]; static uint8_t g_t=0;
static uint32_t g_a=0, g_b=0;      /* zur laufzeit gefaltete "konstanten" */

static uint8_t rr(uint8_t v,int r){r&=7;return (uint8_t)((v>>r)|(v<<(8-r)));}
static uint8_t rl(uint8_t v,int r){r&=7;return (uint8_t)((v<<r)|(v>>(8-r)));}

/* faltet A0 -> ein byte (seed fuer runde 1). wert steht nirgends. */
static uint8_t f0(void){uint8_t s=0;for(int i=0;i<16;i++){s^=A0[i];s=rl(s,3);}return s;}

/* baut die permutationstabelle + inverse global */
static void mk(void){for(int i=0;i<256;i++)T[i]=(uint8_t)((i*167+13)&0xFF);uint8_t k=0x5A;for(int i=0;i<256;i++){k=(uint8_t)(k+T[i]+i);uint8_t t=T[i];T[i]=T[k];T[k]=t;}g_t=1;}
static void mki(uint8_t*iv){if(!g_t)mk();for(int i=0;i<256;i++)iv[T[i]]=(uint8_t)i;}

/* init faltet die verteilten konstanten in globals.
   g_a = R4-kontext (aus P0 rekombiniert), g_b = LCG-seed. */
static void init_state(void){
    g_a = (P0[0]|P0[1]);              /* == 0xC0DE1337 */
    g_b = (P0[2]|P0[3]);              /* == 0x1337C0DE */
}

/* die inverse transformation, bewusst als EIN block mit verschraenkten
   phasen statt fuenf sauberen funktionen. reihenfolge: d5,d4,d3,d2,d1. */
static void reveal(uint8_t*b,int n){
    if(!g_t) mk();
    uint8_t iv[256]; mki(iv);
    /* phase e: lcg-xor (seed g_b) */
    { uint32_t s=g_b; for(int i=0;i<n;i++){s=s*1103515245u+12345u;b[i]=(uint8_t)(b[i]^(uint8_t)(s>>24));} }
    /* phase d: subtraktion rotierender kontext-bytes (g_a) */
    { uint32_t c=g_a; for(int i=0;i<n;i++){uint8_t kb=(uint8_t)(c&0xFF);b[i]=(uint8_t)(b[i]-kb);c=(c>>8)|(c<<24);} }
    /* phase c: overflow-fold rueckwaerts */
    { uint8_t acc=0x3C; for(int i=0;i<n;i++){uint8_t c=b[i];uint8_t p=(uint8_t)(c^acc);acc=(uint8_t)(acc*33+c);b[i]=p;} }
    /* phase b: inverse permutation, verkettet */
    { uint8_t pv=0xA5; for(int i=0;i<n;i++){uint8_t y=b[i];uint8_t ix=iv[y];b[i]=(uint8_t)(ix-pv);pv=y;} }
    /* phase a: additive chaining + rotate rueckwaerts (seed f0) */
    { uint8_t s=f0(),pv=s; for(int i=0;i<n;i++){uint8_t x=b[i],cur=x;x=rr(x,pv&7);x^=pv;x=(uint8_t)(x-s);b[i]=x;pv=cur;} }
}

/* passwort-gate: separat, rollierender hash. */
static uint32_t h(const char*s){uint32_t x=0x1505;for(const char*p=s;*p;p++)x=((x<<5)+x)+(uint8_t)*p;return x;}

int main(int argc,char**argv){
    if(argc!=2){ fprintf(stderr,"usage: %s <password>\n",argv[0]); return 1; }
    init_state();

    if(h(argv[1])==0x3B8023E3u) printf("Access granted. Welcome, licensed user.\n");
    else                         printf("Access denied.\n");

    uint8_t m[20]; for(int i=0;i<19;i++) m[i]=A1[i];
    reveal(m,19); m[19]=0;
    volatile uint8_t z=0; for(int i=0;i<19;i++) z^=m[i]; (void)z;
    return 0;
}
