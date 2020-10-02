#!/bin/bash

L_SAMPLES=( 3000 10000 20000 30000 60000 100000 200000 )
L_SAMPLES_PER_PLAINTEXTS=( 500 1000 4000 8000 )

OUTDIR=./out

mkdir "${OUTDIR}"
cat /proc/cpuinfo > "${OUTDIR}/cpuinfo.txt"
CPUNAME=$(cat /proc/cpuinfo | grep "model name" | uniq | sed -E 's/.*(i[0-9][^ ]*).*/\1/')

for SAMPLES in "${L_SAMPLES[@]}"
do
	echo "Sample size: ${SAMPLES}"
	for SAMPLES_PER_PLAINTEXTS in "${L_SAMPLES_PER_PLAINTEXTS[@]}"
	do
		echo " Samples per Plaintexts: ${SAMPLES_PER_PLAINTEXTS}"
		for ITERATION in {01..10}
		do
			echo "  Iteration ${ITERATION}"
			(time bin/dpa_attacker_v1 ${SAMPLES} ${SAMPLES_PER_PLAINTEXTS}) > "${OUTDIR}/out-dpav1-${CPUNAME}-${SAMPLES}-${SAMPLES_PER_PLAINTEXTS}-${ITERATION}.txt" 2>&1
			killall victim
		done
	done
done
