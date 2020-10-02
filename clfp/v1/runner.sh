#!/bin/bash

L_SAMPLES=( 60000 80000 90000 100000 110000 120000 )

OUTDIR=./out

mkdir "${OUTDIR}"
cat /proc/cpuinfo > "${OUTDIR}/cpuinfo.txt"
CPUNAME=$(cat /proc/cpuinfo | grep "model name" | uniq | sed -E 's/.*(i[0-9][^ ]*).*/\1/')

for SAMPLES in "${L_SAMPLES[@]}"
do
	echo "Sample size: ${SAMPLES}"
	for ITERATION in {01..10}
	do
		echo " Iteration ${ITERATION}"
		(time bin/clfp_attacker_v1 ${SAMPLES}) > "${OUTDIR}/out-clfpv1-${CPUNAME}-${SAMPLES}-${ITERATION}.txt" 2>&1
	done
done

