/*
 * lockbox.c -- Datei-Verschlüsselungswerkzeug
 *
 * Aufruf:
 *   ./lockbox e <keyfile> <password> <infile> <outfile>   (verschluesseln)
 *   ./lockbox d <keyfile> <password> <infile> <outfile>   (entschluesseln)
 *
 * Es gibt KEINE Korrektheitspruefung im Programm -- kein Vergleich, kein
 * Branch auf einen berechneten Geheimwert. Das Programm wendet lediglich
 * eine Transformation (XOR mit einem aus keyfile+password abgeleiteten
 * Keystream) auf die Eingabedatei an. Falsches Passwort -> falscher
 * Keystream -> Ausgabe ist Muell, aber es gibt keinen Ort, an dem ein
 * "richtiger" Wert im Speicher steht, den man per Debugger abgreifen koennte.
 *
 * Sicherheitsproblem: Das Passwort geht nur als EIN konstantes Maskenbyte
 * in den Keystream ein (nicht positionsabhaengig). Bei bekanntem
 * Klartext-Praefix laesst sich dieses eine Byte direkt berechnen -- mit
 * mehrfacher Bestaetigung, ohne Suche. Der Keyfile-Anteil des Keystreams
 * ist vollstaendig aus dem (mitgelieferten) keyfile und dem im Binary
 * sichtbaren Algorithmus rekonstruierbar.
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static uint8_t SBOX[256]; static uint8_t SI=0;

static uint8_t rl(uint8_t v,int r){r&=7;return (uint8_t)((v<<r)|(v>>(8-r)));}

static void sbox_build(void){
    for(int i=0;i<256;i++) SBOX[i]=(uint8_t)((i*167+13)&0xFF);
    uint8_t k=0x5A;
    for(int i=0;i<256;i++){ k=(uint8_t)(k+SBOX[i]+i); uint8_t t=SBOX[i]; SBOX[i]=SBOX[k]; SBOX[k]=t; }
    SI=1;
}

static uint8_t fold_key(const uint8_t*kf){
    uint8_t s=0; for(int i=0;i<16;i++){ s^=kf[i]; s=rl(s,3); } return s;
}

static void kdf(const uint8_t*keyfile, uint8_t*out, int n){
    if(!SI) sbox_build();
    uint8_t seed = fold_key(keyfile);
    uint32_t state = ((uint32_t)seed<<24) | ((uint32_t)keyfile[1]<<16) | ((uint32_t)keyfile[2]<<8) | keyfile[3];
    uint8_t prev = seed;
    for(int i=0;i<n;i++){
        state = state*1103515245u + 12345u;
        uint8_t x = (uint8_t)(state>>24);
        x = SBOX[(uint8_t)(x + prev)];
        x = rl(x, prev & 7);
        out[i] = x;
        prev = x;
    }
}

static uint8_t pw_mask(const char*password){
    uint8_t m=0xA5;
    for(const char*p=password;*p;p++) m=(uint8_t)(m*31 + (uint8_t)*p);
    return m;
}

static uint8_t*read_all(const char*path,long*len){
    FILE*f=fopen(path,"rb"); if(!f){ perror("open"); exit(1); }
    fseek(f,0,SEEK_END); long n=ftell(f); fseek(f,0,SEEK_SET);
    uint8_t*buf=malloc((size_t)n);
    if(fread(buf,1,(size_t)n,f)!=(size_t)n){ perror("read"); exit(1); }
    fclose(f); *len=n; return buf;
}

int main(int argc,char**argv){
    if(argc!=6 || (argv[1][0]!='e' && argv[1][0]!='d')){
        fprintf(stderr,"usage: %s <e|d> <keyfile> <password> <infile> <outfile>\n", argv[0]);
        return 1;
    }
    const char*keyfile_path=argv[2];
    const char*password=argv[3];
    const char*infile=argv[4];
    const char*outfile=argv[5];

    long kn; uint8_t*keyfile=read_all(keyfile_path,&kn);
    if(kn<16){ fprintf(stderr,"keyfile too short (need >=16 bytes)\n"); return 1; }

    long n; uint8_t*data=read_all(infile,&n);

    uint8_t*ks=malloc((size_t)n);
    kdf(keyfile, ks, (int)n);
    uint8_t m = pw_mask(password);
    for(long i=0;i<n;i++) data[i] = (uint8_t)(data[i] ^ ks[i] ^ m);

    FILE*out=fopen(outfile,"wb");
    if(!out){ perror("open out"); return 1; }
    fwrite(data,1,(size_t)n,out);
    fclose(out);

    fprintf(stderr,"%s: %ld bytes -> %s\n", argv[1][0]=='e'?"encrypted":"decrypted", n, outfile);
    return 0;
}
