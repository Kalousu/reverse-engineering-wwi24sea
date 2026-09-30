/*
 * lv.c -- "LicenseGuard" (gehärtete Fassung)
 *
 * Aufruf:  ./lv <lizenzschluessel>
 *
 *   Gültiger Schlüssel  -> "Access granted. Welcome, licensed user."
 *   Ungültiger Schlüssel -> "Access denied."
 *
 * Der gültige Lizenzschlüssel wird NICHT im Klartext gespeichert. Er liegt
 * verschlüsselt in .rodata (A1[]) und wird zur Laufzeit mit einem fest im
 * Binary hinterlegten, symmetrischen Verfahren entschlüsselt und dann mit der
 * Eingabe verglichen.
 *
 * Sicherheitsproblem: Da das Entschlüsselungsverfahren und alle Konstanten im
 * Binary liegen und jede Runde invertierbar ist, kann ein Angreifer den
 * gültigen Schlüssel rekonstruieren, ohne ihn zu erraten. Der Schlüssel ist
 * zugleich die Flag: FLAG{...}.
 *
 * Härtung (ändert NICHT den Algorithmus, nur die Lesbarkeit):
 *  - Rundenkonstanten werden zur Laufzeit aus mehreren Quellen gefaltet.
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

static uint8_t f0(void){uint8_t s=0;for(int i=0;i<16;i++){s^=A0[i];s=rl(s,3);}return s;}

static void mk(void){for(int i=0;i<256;i++)T[i]=(uint8_t)((i*167+13)&0xFF);uint8_t k=0x5A;for(int i=0;i<256;i++){k=(uint8_t)(k+T[i]+i);uint8_t t=T[i];T[i]=T[k];T[k]=t;}g_t=1;}
static void mki(uint8_t*iv){if(!g_t)mk();for(int i=0;i<256;i++)iv[T[i]]=(uint8_t)i;}

static void init_state(void){
    g_a = (P0[0]|P0[1]);              /* == 0xC0DE1337 */
    g_b = (P0[2]|P0[3]);              /* == 0x1337C0DE */
}

/* inverse transformation (d5,d4,d3,d2,d1), verschraenkt als ein block. */
static void reveal(uint8_t*b,int n){
    if(!g_t) mk();
    uint8_t iv[256]; mki(iv);
    { uint32_t s=g_b; for(int i=0;i<n;i++){s=s*1103515245u+12345u;b[i]=(uint8_t)(b[i]^(uint8_t)(s>>24));} }
    { uint32_t c=g_a; for(int i=0;i<n;i++){uint8_t kb=(uint8_t)(c&0xFF);b[i]=(uint8_t)(b[i]-kb);c=(c>>8)|(c<<24);} }
    { uint8_t acc=0x3C; for(int i=0;i<n;i++){uint8_t c=b[i];uint8_t p=(uint8_t)(c^acc);acc=(uint8_t)(acc*33+c);b[i]=p;} }
    { uint8_t pv=0xA5; for(int i=0;i<n;i++){uint8_t y=b[i];uint8_t ix=iv[y];b[i]=(uint8_t)(ix-pv);pv=y;} }
    { uint8_t s=f0(),pv=s; for(int i=0;i<n;i++){uint8_t x=b[i],cur=x;x=rr(x,pv&7);x^=pv;x=(uint8_t)(x-s);b[i]=x;pv=cur;} }
}

/* konstante-zeit-vergleich, damit die laenge/inhalt kein timing-orakel gibt */
static int eq_ct(const uint8_t*a,const uint8_t*b,int n){
    uint8_t d=0; for(int i=0;i<n;i++) d|=(uint8_t)(a[i]^b[i]); return d==0;
}

int main(int argc,char**argv){
    if(argc!=2){ fprintf(stderr,"usage: %s <license-key>\n",argv[0]); return 1; }
    init_state();

    /* gueltigen schluessel (=flag) zur laufzeit aus A1[] entschluesseln */
    uint8_t key[19];
    for(int i=0;i<19;i++) key[i]=A1[i];
    reveal(key,19);                   /* key enthaelt nun den gueltigen schluessel */

    /* eingabe vergleichen: exakt 19 zeichen und gleicher inhalt */
    const char*in=argv[1];
    int ok = (strlen(in)==19) && eq_ct((const uint8_t*)in,key,19);

    if(ok) printf("Access granted. Welcome, licensed user.\n");
    else   printf("Access denied.\n");

    /* key nicht wegoptimieren lassen */
    volatile uint8_t z=0; for(int i=0;i<19;i++) z^=key[i]; (void)z;
    return ok?0:1;
}
