/* solve.c -- Referenz-Loesung.
 * Nutzt NUR: keyfile (shipped), secret.txt.enc (shipped), den aus dem
 * Binary rekonstruierten KDF-Algorithmus, und die Annahme "Klartext
 * beginnt mit FLAG{". KEIN Passwort, KEIN Bruteforce, KEIN Debugger. */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static uint8_t SBOX[256]; static uint8_t SI=0;
static uint8_t rl(uint8_t v,int r){r&=7;return (uint8_t)((v<<r)|(v>>(8-r)));}
static void sbox_build(void){for(int i=0;i<256;i++)SBOX[i]=(uint8_t)((i*167+13)&0xFF);uint8_t k=0x5A;for(int i=0;i<256;i++){k=(uint8_t)(k+SBOX[i]+i);uint8_t t=SBOX[i];SBOX[i]=SBOX[k];SBOX[k]=t;}SI=1;}
static uint8_t fold_key(const uint8_t*kf){uint8_t s=0;for(int i=0;i<16;i++){s^=kf[i];s=rl(s,3);}return s;}
static void kdf(const uint8_t*keyfile,uint8_t*out,int n){
    if(!SI)sbox_build();
    uint8_t seed=fold_key(keyfile);
    uint32_t state=((uint32_t)seed<<24)|((uint32_t)keyfile[1]<<16)|((uint32_t)keyfile[2]<<8)|keyfile[3];
    uint8_t prev=seed;
    for(int i=0;i<n;i++){state=state*1103515245u+12345u;uint8_t x=(uint8_t)(state>>24);x=SBOX[(uint8_t)(x+prev)];x=rl(x,prev&7);out[i]=x;prev=x;}
}

static uint8_t*read_all(const char*path,long*len){
    FILE*f=fopen(path,"rb"); if(!f){perror("open");exit(1);}
    fseek(f,0,SEEK_END); long n=ftell(f); fseek(f,0,SEEK_SET);
    uint8_t*b=malloc((size_t)n); if(fread(b,1,(size_t)n,f)!=(size_t)n){perror("read");exit(1);}
    fclose(f); *len=n; return b;
}

int main(int argc,char**argv){
    if(argc!=3){ fprintf(stderr,"usage: %s <keyfile> <ciphertext>\n",argv[0]); return 1; }
    long kn; uint8_t*keyfile=read_all(argv[1],&kn);
    long n;  uint8_t*ct=read_all(argv[2],&n);

    uint8_t*ks=malloc((size_t)n);
    kdf(keyfile, ks, (int)n);

    const char*known="FLAG{"; int kcount=5;
    if(n<kcount){ fprintf(stderr,"file too short for known-plaintext\n"); return 1; }

    uint8_t votes[5];
    for(int i=0;i<kcount;i++) votes[i]=(uint8_t)(ct[i]^ks[i]^(uint8_t)known[i]);
    int consistent=1; for(int i=1;i<kcount;i++) if(votes[i]!=votes[0]) consistent=0;
    fprintf(stderr,"[*] mask votes: ");
    for(int i=0;i<kcount;i++) fprintf(stderr,"%02X ",votes[i]);
    fprintf(stderr,"\n[%s] konsistent (M=0x%02X)\n", consistent?"+":"-", votes[0]);
    if(!consistent){ fprintf(stderr,"[-] known-plaintext assumption failed\n"); return 1; }

    uint8_t m=votes[0];
    uint8_t*pt=malloc((size_t)n);
    for(long i=0;i<n;i++) pt[i]=(uint8_t)(ct[i]^ks[i]^m);

    printf("RECOVERED: ");
    fwrite(pt,1,(size_t)n,stdout);
    printf("\n");
    return 0;
}
