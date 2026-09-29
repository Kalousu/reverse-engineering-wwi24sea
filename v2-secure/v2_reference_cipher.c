/* cipher.c -- the flag cipher, designed invertible-first.
 *
 * enc(flag) -> CIPHER (done at build time, stored in binary)
 * dec(CIPHER) -> flag  (this is what the binary does internally, and what
 *                       the solver reconstructs from the disassembly)
 *
 * ALL round constants are fixed and visible. No key, no search.
 * Decryption = applying inverse rounds. The "secret" recovered IS the flag.
 *
 * 5 rounds, each with a deliberate Ghidra-friction property but each
 * uniquely invertible (validated per-round below).
 */
#include <stdint.h>
#include <stdio.h>
#include <string.h>

/* ---- fixed embedded data (all visible in .rodata) ---- */
static const uint8_t TBL[16]={0x9E,0x37,0x79,0xB9,0x7F,0x4A,0x7C,0x15,0xF3,0x9C,0xC0,0x60,0x51,0x2D,0xA3,0x1B};
static uint8_t SBOX[256], INV[256]; static uint8_t SBOX_INIT=0;

static uint8_t rotl8(uint8_t v,int r){r&=7;return (uint8_t)((v<<r)|(v>>(8-r)));}
static uint8_t rotr8(uint8_t v,int r){r&=7;return (uint8_t)((v>>r)|(v<<(8-r)));}
static uint8_t fold_seed(void){uint8_t s=0;for(int i=0;i<16;i++){s^=TBL[i];s=(uint8_t)((s<<3)|(s>>5));}return s;}
static void sbox_build(void){for(int i=0;i<256;i++)SBOX[i]=(uint8_t)((i*167+13)&0xFF);uint8_t k=0x5A;for(int i=0;i<256;i++){k=(uint8_t)(k+SBOX[i]+i);uint8_t t=SBOX[i];SBOX[i]=SBOX[k];SBOX[k]=t;}for(int i=0;i<256;i++)INV[SBOX[i]]=(uint8_t)i;SBOX_INIT=1;}

/* R1: additive chaining + data-dependent rotate. seed folded at runtime. */
static void e1(uint8_t*b,int n){uint8_t seed=fold_seed(),prev=seed;for(int i=0;i<n;i++){uint8_t x=b[i];x=(uint8_t)(x+seed);x^=prev;x=rotl8(x,prev&7);b[i]=x;prev=x;}}
static void d1(uint8_t*b,int n){uint8_t seed=fold_seed(),prev=seed;for(int i=0;i<n;i++){uint8_t x=b[i],cur=x;x=rotr8(x,prev&7);x^=prev;x=(uint8_t)(x-seed);b[i]=x;prev=cur;}}

/* R2: S-box substitution with data-dependent index (chained on output). */
static void e2(uint8_t*b,int n){if(!SBOX_INIT)sbox_build();uint8_t prev=0xA5;for(int i=0;i<n;i++){uint8_t idx=(uint8_t)(b[i]+prev);uint8_t y=SBOX[idx];b[i]=y;prev=y;}}
static void d2(uint8_t*b,int n){if(!SBOX_INIT)sbox_build();uint8_t prev=0xA5;for(int i=0;i<n;i++){uint8_t y=b[i];uint8_t idx=INV[y];uint8_t x=(uint8_t)(idx-prev);prev=y;b[i]=x;}}

/* R3: overflow-fold accumulator, chained on ciphertext byte (uniquely invertible). */
static void e3(uint8_t*b,int n){uint8_t acc=0x3C;for(int i=0;i<n;i++){uint8_t c=(uint8_t)(b[i]^acc);acc=(uint8_t)(acc*33+c);b[i]=c;}}
static void d3(uint8_t*b,int n){uint8_t acc=0x3C;for(int i=0;i<n;i++){uint8_t c=b[i];uint8_t p=(uint8_t)(c^acc);acc=(uint8_t)(acc*33+c);b[i]=p;}}

/* R4: position-dependent add from a rotating fixed constant CTX (visible). */
#define CTX 0xC0DE1337u
static void e4(uint8_t*b,int n){uint32_t c=CTX;for(int i=0;i<n;i++){uint8_t kb=(uint8_t)(c&0xFF);b[i]=(uint8_t)(b[i]+kb);c=(c>>8)|(c<<24);}}
static void d4(uint8_t*b,int n){uint32_t c=CTX;for(int i=0;i<n;i++){uint8_t kb=(uint8_t)(c&0xFF);b[i]=(uint8_t)(b[i]-kb);c=(c>>8)|(c<<24);}}

/* R5: LCG keystream XOR (fixed seed, visible). The named weakness. */
#define LCG_SEED 0x1337C0DEu
static void e5(uint8_t*b,int n){uint32_t s=LCG_SEED;for(int i=0;i<n;i++){s=s*1103515245u+12345u;uint8_t ks=(uint8_t)(s>>24);b[i]=(uint8_t)(b[i]^ks);}}
static void d5(uint8_t*b,int n){uint32_t s=LCG_SEED;for(int i=0;i<n;i++){s=s*1103515245u+12345u;uint8_t ks=(uint8_t)(s>>24);b[i]=(uint8_t)(b[i]^ks);}}

/* full encrypt / decrypt */
static void encrypt(uint8_t*b,int n){e1(b,n);e2(b,n);e3(b,n);e4(b,n);e5(b,n);}
static void decrypt(uint8_t*b,int n){d5(b,n);d4(b,n);d3(b,n);d2(b,n);d1(b,n);}

static int rt(const char*name,void(*e)(uint8_t*,int),void(*d)(uint8_t*,int)){
    uint8_t o[19],w[19]; for(int i=0;i<19;i++)o[i]=(uint8_t)(i*11+5); memcpy(w,o,19);
    e(w,19); d(w,19); int ok=memcmp(o,w,19)==0;
    printf("[%s] %s round-trip\n", ok?"+":"-", name); return ok;
}

int main(void){
    /* per-round proofs */
    rt("R1",e1,d1); rt("R2",e2,d2); rt("R3",e3,d3); rt("R4",e4,d4); rt("R5",e5,d5);

    /* full chain on the actual flag */
    const char*flag="FLAG{4cc3ss_d3n13d}";
    int n=(int)strlen(flag);
    uint8_t buf[20]; memcpy(buf,flag,n);
    encrypt(buf,n);
    printf("\nCIPHER[19] = {");
    for(int i=0;i<n;i++) printf("0x%02X%s",buf[i], i<n-1?",":"");
    printf("};\n");

    /* prove decrypt recovers the flag */
    decrypt(buf,n); buf[n]=0;
    printf("decrypted  = %s\n", buf);
    printf("[%s] full flag recovery\n", strcmp((char*)buf,flag)==0?"+":"-");
    return 0;
}
