#!/bin/bash

#	Disable frequency scaling until the next boot. Intel:
#		echo 1 > /sys/devices/system/cpu/intel_pstate/no_turbo
#	AMD:
#		echo 0 > /sys/devices/system/cpu/cpufreq/boost

for dut in \
	RACCOON_128_1	RACCOON_128_2	RACCOON_128_4	\
	RACCOON_128_8	RACCOON_128_16	RACCOON_128_32	\
	RACCOON_192_1	RACCOON_192_2	RACCOON_192_4	\
	RACCOON_192_8	RACCOON_192_16	RACCOON_192_32	\
	RACCOON_256_1	RACCOON_256_2	RACCOON_256_4	\
	RACCOON_256_8	RACCOON_256_16	RACCOON_256_32
do
	logf=bench_$dut.txt
	echo === $logf ===
	make obj-clean
	make RACCF="-D"$dut" -DBENCH_TIMEOUT=2.0"
	./xtest | tee $logf
	grep -e '_core_keygen' -e '_core_sign' -e '_core_verify' racc_core.su >> $logf
done
