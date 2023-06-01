#! /bin/bash

for x in *.rsp
do
	echo -n `head -1 $x | colrm 1 2`$':\t' | expand
	sha256sum $x
done
