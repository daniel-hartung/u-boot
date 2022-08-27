#!/bin/bash
echo '##Creating SHA-256 Hash of u-boot.bin##'
xxd -plain ../u-boot-hash-test.bin | tr -d '\n' | tr a-z A-Z | sha256sum
xxd -plain ../u-boot-hash-test.bin | tr -d '\n' | tr a-z A-Z | sha256sum > digest_uboot.txt
xxd -r -p digest_uboot.txt > digest_uboot.bin
echo '##Created digest_uboot.bin##'

echo '##Creating signature of digest_uboot.bin##'
openssl pkeyutl -sign -inkey private.ec.key -in digest_uboot.bin > signature_uboot.bin
#openssl dgst -sha256 -sign private.ec.key -out signature_uboot.txt digest_uboot.txt
#cat signature_uboot.txt
echo '##Created signature_uboot.bin##'
# Funktioniert nicht so wie geplant, weil es immer eine unterschiedliche Länge hat...why?
echo '##Extracting R and S value of the signature ##'
openssl asn1parse -in signature_uboot.bin -inform der -out signature.bin
cat signature.bin|cut -c5-36,40-71| tr -d '\n' > signature_rs_uboot.bin
echo '##R and S value extracted into signature_rs_uboot.bin##'
xxd signature_uboot.bin


#echo 'Verifying signature, hash and public key...'
#openssl dgst -sha256 -verify public.pem -signature signature_uboot.txt digest_uboot.txt

#xxd -plain signature_uboot.txt | tr -d '\n' | tr a-z A-Z > signature_uboot_hex.txt




# für key generation
# openssl ec -pubin -inform pem -in public.pem -out public.der -outform DER
# openssl ec -pubin -in public.pem -text -noout > publickey.txt

# xxd -r -p digest_uboot.txt > digest_uboot.bin
# openssl pkeyutl -sign -inkey private.ec.key -in digest_uboot.bin > signature_uboot.bin
# openssl asn1parse -in signature_uboot.txt -inform der -out test.txt
