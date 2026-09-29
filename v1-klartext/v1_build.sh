#!/usr/bin/env bash
# build.sh -- baut das ungehärtete Challenge-Binary (v1)
set -e

echo "[*] Kompiliere validator (ungehärtet)..."
gcc -O2 -o validator v1_validator.c

echo "[*] Kompiliere Referenz-Cipher (Beweis der Invertierbarkeit)..."
gcc -O2 -o reference_cipher v1_reference_cipher.c

echo "[*] Kompiliere Musterlösung..."
gcc -O2 -o solve v1_solve.c

echo ""
echo "[+] Fertig. Test:"
echo "    ./validator hello                  -> Access denied."
echo "    ./validator s3cr3t_l1c3ns3_k3y     -> Access granted."
echo "    ./solve                            -> RECOVERED FLAG: FLAG{...}"
