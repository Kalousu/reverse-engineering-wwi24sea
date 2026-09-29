/*
 * validator.c  --  "License Validator" challenge binary
 *
 * Usage: ./validator <password>
 *
 *   Wrong password -> "Access denied."
 *   Right password -> "Access granted. Welcome, licensed user."
 *
 * The flag FLAG{...} is NOT printed by the program and is NOT the password.
 * It sits encrypted in .rodata (CIPHER[]) and is decrypted by decrypt_flag()
 * using only fixed, in-binary constants. The password check is a SEPARATE
 * mechanism (a hash comparison) and does not protect the flag at all.
 *
 * Intended break: reverse the 5-round cipher, run it backwards on CIPHER[],
 * recover the flag. The password gate is a decoy / bypassable control.
 */
#include <stdint.h>
#include <stdio.h>
#include <string.h>

/* ---- embedded, all visible in .rodata ---- */
static const uint8_t TBL[16]={0x9E,0x37,0x79,0xB9,0x7F,0x4A,0x7C,0x15,0xF3,0x9C,0xC0,0x60,0x51,0x2D,0xA3,0x1B};
static const uint8_t CIPHER[19]={0x84,0xC3,0x37,0x2E,0x43,0x88,0x10,0x41,0x76,0xB4,0x14,0xE6,0x62,0x16,0xC4,0xA4,0x39,0x32,0xF3};

static uint8_t SBOX[256];
static uint8_t SBOX_INIT=0;

static uint8_t rotl8(uint8_t v,int r){r&=7;return (uint8_t)((v<<r)|(v>>(8-r)));}
static uint8_t rotr8(uint8_t v,int r){r&=7;return (uint8_t)((v>>r)|(v<<(8-r)));}
static uint8_t fold_seed(void){uint8_t s=0;for(int i=0;i<16;i++){s^=TBL[i];s=(uint8_t)((s<<3)|(s>>5));}return s;}
static void sbox_build(void){for(int i=0;i<256;i++)SBOX[i]=(uint8_t)((i*167+13)&0xFF);uint8_t k=0x5A;for(int i=0;i<256;i++){k=(uint8_t)(k+SBOX[i]+i);uint8_t t=SBOX[i];SBOX[i]=SBOX[k];SBOX[k]=t;}SBOX_INIT=1;}
static void inv_build(uint8_t*inv){if(!SBOX_INIT)sbox_build();for(int i=0;i<256;i++)inv[SBOX[i]]=(uint8_t)i;}

/* ---- inverse rounds (this is what the binary runs to reveal the flag) ---- */
static void d1(uint8_t*b,int n){uint8_t seed=fold_seed(),prev=seed;for(int i=0;i<n;i++){uint8_t x=b[i],cur=x;x=rotr8(x,prev&7);x^=prev;x=(uint8_t)(x-seed);b[i]=x;prev=cur;}}
static void d2(uint8_t*b,int n){uint8_t inv[256];inv_build(inv);uint8_t prev=0xA5;for(int i=0;i<n;i++){uint8_t y=b[i];uint8_t idx=inv[y];uint8_t x=(uint8_t)(idx-prev);prev=y;b[i]=x;}}
static void d3(uint8_t*b,int n){uint8_t acc=0x3C;for(int i=0;i<n;i++){uint8_t c=b[i];uint8_t p=(uint8_t)(c^acc);acc=(uint8_t)(acc*33+c);b[i]=p;}}
#define CTX 0xC0DE1337u
static void d4(uint8_t*b,int n){uint32_t c=CTX;for(int i=0;i<n;i++){uint8_t kb=(uint8_t)(c&0xFF);b[i]=(uint8_t)(b[i]-kb);c=(c>>8)|(c<<24);}}
#define LCG_SEED 0x1337C0DEu
static void d5(uint8_t*b,int n){uint32_t s=LCG_SEED;for(int i=0;i<n;i++){s=s*1103515245u+12345u;uint8_t ks=(uint8_t)(s>>24);b[i]=(uint8_t)(b[i]^ks);}}

static void decrypt_flag(uint8_t*out,int n){
    for(int i=0;i<n;i++) out[i]=CIPHER[i];
    d5(out,n); d4(out,n); d3(out,n); d2(out,n); d1(out,n);
}

/* ---- password gate: SEPARATE from the flag. A simple rolling hash compare. ---- */
static uint32_t pw_hash(const char*s){
    uint32_t h=0x1505;                 /* djb2-ish */
    for(const char*p=s;*p;p++) h=((h<<5)+h)+(uint8_t)*p;
    return h;
}
/* precomputed hash of the real password (computed at build, see note) */
#define PW_HASH 0x3B8023E3u

int main(int argc,char**argv){
    if(argc!=2){ fprintf(stderr,"usage: %s <password>\n",argv[0]); return 1; }

    if(pw_hash(argv[1])==PW_HASH){
        printf("Access granted. Welcome, licensed user.\n");
    } else {
        printf("Access denied.\n");
    }

    /* The flag is decrypted here but only used internally (e.g. as an
       integrity token). It is never printed. It exists in memory and,
       more importantly, in CIPHER[] + this code -> fully recoverable by RE. */
    uint8_t flag[20];
    decrypt_flag(flag,19); flag[19]=0;
    volatile uint8_t sink=0; for(int i=0;i<19;i++) sink^=flag[i]; /* prevent optimizing away */
    (void)sink;
    return 0;
}
