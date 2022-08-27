#!/bin/bash
#u-boot cross compile
#source /opt/ssd/3.4.1/environment-setup-cortexa8hf-neon-ssd-linux-gnueabi # doesn't work like that in scripts?
#export CROSS_COMPILE=arm-ssd-linux-gnueabi-
export PATH=/home/daniel/gcc-arm-11.2-2022.02-x86_64-arm-none-eabi/bin:$PATH 
export CROSS_COMPILE=arm-none-eabi-
export ARCH=arm
# make ams1xx_defconfig
make $1

