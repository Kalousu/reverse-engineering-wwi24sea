/* final_solve.c -- the INTENDED SOLUTION.
 * Uses ONLY what a reverse-engineer reads from the disassembly:
 *   - CIPHER[] bytes (from .rodata)
 *   - TBL[] bytes (from .rodata)
 *   - the 5 round algorithms and their constants
 * Recovers the flag WITHOUT the password and WITHOUT running the target. */
#include <stdint.h>
#include <stdio.h>

static const uint8_t TBL[16]={0x9E,0x37,0x79,0xB9,0x7F,0x4A,0x7C,0x15,0xF3,0x9C,0xC0,0x60,0x51,0x2D,0xA3,0x1B};
static const uint8_t CIPHER[19]={0x84,0xC3,0x37,0x2E,0x43,0x88,0x10,0x41,0x76,0xB4,0x14,0xE6,0x62,0x16,0xC4,0xA4,0x39,0x32,0xF3};
static uint8_t SBOX[256],INV[256];static uint8_t SI=0;
static uint8_t rotr8(uint8_t v,int r){r&=7;return (uint8_t)((v>>r)|(v<<(8-r)));}
static uint8_t fold_seed(void){uint8_t s=0;for(int i=0;i<16;i++){s^=TBL[i];s=(uint8_t)((s<<3)|(s>>5));}return s;}
static void sb(void){for(int i=0;i<256;i++)SBOX[i]=(uint8_t)((i*167+13)&0xFF);uint8_t k=0x5A;for(int i=0;i<256;i++){k=(uint8_t)(k+SBOX[i]+i);uint8_t t=SBOX[i];SBOX[i]=SBOX[k];SBOX[k]=t;}for(int i=0;i<256;i++)INV[SBOX[i]]=(uint8_t)i;SI=1;}
static void d1(uint8_t*b,int n){uint8_t s=fold_seed(),pv=s;for(int i=0;i<n;i++){uint8_t x=b[i],c=x;x=rotr8(x,pv&7);x^=pv;x=(uint8_t)(x-s);b[i]=x;pv=c;}}
static void d2(uint8_t*b,int n){if(!SI)sb();uint8_t pv=0xA5;for(int i=0;i<n;i++){uint8_t y=b[i];uint8_t ix=INV[y];uint8_t x=(uint8_t)(ix-pv);pv=y;b[i]=x;}}
static void d3(uint8_t*b,int n){uint8_t acc=0x3C;for(int i=0;i<n;i++){uint8_t c=b[i];uint8_t p=(uint8_t)(c^acc);acc=(uint8_t)(acc*33+c);b[i]=p;}}
static void d4(uint8_t*b,int n){uint32_t c=0xC0DE1337u;for(int i=0;i<n;i++){uint8_t kb=(uint8_t)(c&0xFF);b[i]=(uint8_t)(b[i]-kb);c=(c>>8)|(c<<24);}}
static void d5(uint8_t*b,int n){uint32_t s=0x1337C0DEu;for(int i=0;i<n;i++){s=s*1103515245u+12345u;uint8_t ks=(uint8_t)(s>>24);b[i]=(uint8_t)(b[i]^ks);}}
int main(){
    uint8_t b[20]; for(int i=0;i<19;i++)b[i]=CIPHER[i];
    d5(b,19);d4(b,19);d3(b,19);d2(b,19);d1(b,19); b[19]=0;
    printf("RECOVERED FLAG: %s\n",b);
    return 0;
}
