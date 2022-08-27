#!/bin/bash

DOPTS="-I dts -O dtb -p 0x1000"
key_dir="../keys-test"
key_name="dev" # doesn't matter rn?
FIT_IMG="galileo.itb"
CTRL_FDT="am335x-galileo.dtb"

echo "--- Creating FIT Image ---\n"

mkimage -f galileo.its galileo.itb

echo "\n--- Signing FIT Image ---\n"

mkimage -D "${DOPTS}" -F -k "${key_dir}" -K ${CTRL_FDT} -r "${FIT_IMG}"

# zum erstellen eines u-boot images ohne device tree
cp ../u-boot-nodtb.bin u-boot-nodtb.bin
mkimage -A arm -T firmware -C none -O u-boot -a 0x80800000 -e 0x80800000 -n "U-Boot board" -d u-boot-nodtb.bin u-boot-nodtb.img

# zum erstellen eines u-boot images mit den keys (?)
cat u-boot-nodtb.img am335x-galileo.dtb > u-boot-wdtb.img

# tools/fit_check_sign -f fit/galileo.itb -k fit/am335x-galileo.dtb
# zum testen auf der VM

# openssl genpkey -algorithm RSA -out dev-key.key -pkeyopt rsa_keygen_bits:2048 -pkeyopt rsa_keygen_pubexp:65537
# openssl req -batch -new -x509 -key dev-key.key -out dev-key.crt
# Key generieren
