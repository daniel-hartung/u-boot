U-Boot Verified Boot for Galileo

--------------------------------

Execute the script 'generate-verified-boot-files.sh':

	sh generate-verified-boot-files.sh

It will create the files needed for the U-Boot's Verified Boot:

	- galileo.itb
	- u-boot-wdtb.img

'galileo.itb' is a FIT-Image, that contains the kernel and device tree binary.
'u-boot-wdtb.img' is the U-Boot image with the device tree attached at the end.


These files have to be flashed into the flash memory of the galileo board.
For now we flash the FIT-Image into the space of the B-Side kernel. 
Here is an example how the flash commands could look like:

	FLASHFILE.Erase 0x00180000--0x0027FFFF
	FLASHFILE.load X:\path\to\u-boot-wdtb.img 0x00180000
	FLASHFILE.Erase 0x00A00000--0x00FFFFFF
	FLASHFILE.load X:\path\to\galileo.itb 0x00A00000


Currently the boot process is not automated for the verified boot, so you have to enter the following code in the U-Boot command line to use it successfully:

	setenv verify yes
	nand read 84000000 kernelB
	bootm 84000000


These steps will boot the kernel after it has been verified by the verified boot function of U-Boot.
