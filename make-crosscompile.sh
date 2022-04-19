#!/bin/bash
#u-boot cross compile
source /opt/ssd/3.4.1/environment-setup-cortexa8hf-neon-ssd-linux-gnueabi
export CROSS_COMPILE=arm-ssd-linux-gnueabi-
export ARCH=arm
# make ams1xx_defconfig
make

