#!/bin/bash

make clean
mkdir -p kat

for iut in \
	RACCOON_128_1	RACCOON_128_2	RACCOON_128_4	\
	RACCOON_128_8	RACCOON_128_16	RACCOON_128_32	\
	RACCOON_192_1	RACCOON_192_2	RACCOON_192_4	\
	RACCOON_192_8	RACCOON_192_16	RACCOON_192_32	\
	RACCOON_256_1	RACCOON_256_2	RACCOON_256_4	\
	RACCOON_256_8	RACCOON_256_16	RACCOON_256_32
do
	echo	=== $iut ===
	make -f Makefile.kat IUT="$iut" obj-clean
	make -f Makefile.kat IUT="$iut"
	cd kat
	./xgen_$iut
	cd ..
done
