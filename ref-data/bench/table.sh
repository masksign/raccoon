#!/bin/bash

for kappa in 128 192 256
do
    echo '\hline'
    for d in 1 2 4 8 16 32
    do
        fn="bench_RACCOON_${kappa}_${d}.txt"
        echo -n $kappa-$d
        echo -n '&' `grep 'KeyGen()'    $fn | cut -f 3 | tr -dc '0-9.'`
        echo -n '&' `grep 'KeyGen()'    $fn | cut -f 4 | tr -dc '0-9.'`
        echo -n '&' `grep 'core_keygen' $fn | cut -f 2 | tr -dc '0-9.'`
        echo -n '&' `grep 'Sign()'      $fn | cut -f 3 | tr -dc '0-9.'`
        echo -n '&' `grep 'Sign()'      $fn | cut -f 4 | tr -dc '0-9.'`
        echo -n '&' `grep 'core_sign'   $fn | cut -f 2 | tr -dc '0-9.'`
        if [ "$d" -eq "1" ]
        then
            echo -n '&' `grep 'Verify()'    $fn | cut -f 3 | tr -dc '0-9.'`
            echo -n '&' `grep 'Verify()'    $fn | cut -f 4 | tr -dc '0-9.'`
            echo -n '&' `grep 'core_verify' $fn | cut -f 2 | tr -dc '0-9.'`
        else
            echo -n '& = & = & = '
        fi
        echo '\\'
    done
done
