#!/bin/bash

L_SAMPLES=( 200000 400000 600000 800000 )
L_SAMPLES_PER_PLAINTEXTS=( 300 500 1000 )

OUTDIR=./out

mkdir "${OUTDIR}"
cat /proc/cpuinfo > "${OUTDIR}/cpuinfo.txt"
CPUNAME=$(cat /proc/cpuinfo | grep "model name" | uniq | sed -E 's/.*((i|E)[0-9][^ ]*).*/\1/')

for SAMPLES in "${L_SAMPLES[@]}"
do
	echo "Sample size: ${SAMPLES}"
	for SAMPLES_PER_PLAINTEXTS in "${L_SAMPLES_PER_PLAINTEXTS[@]}"
	do
		echo " Samples per Plaintexts: ${SAMPLES_PER_PLAINTEXTS}"
		for ITERATION in {01..10}
		do
			echo "  Iteration ${ITERATION}"
			(time bin/dpa_attacker_v2 ${SAMPLES} ${SAMPLES_PER_PLAINTEXTS}) > "${OUTDIR}/out-dpav2-${CPUNAME}-${SAMPLES}-${SAMPLES_PER_PLAINTEXTS}-${ITERATION}.txt" 2>&1
			killall victim
		done
	done
done
