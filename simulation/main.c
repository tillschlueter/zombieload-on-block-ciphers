#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "aes-min/aes-min.h"

#define NUM_EXPERIMENTS 200000
#define NUM_IT 11

// Select the values to be used to find matching samples
#define USE_AFTER_ADDROUNDKEY 0
#define USE_AFTER_SUBBYTES    1
#define USE_AFTER_SHIFTROWS   0

const uint8_t sr_index_mapping[] = {
	 0, 13, 10,  7,
	 4,  1, 14, 11,
	 8,  5,  2, 15,
	12,  9,  6,  3
};

// returns the maximum value of an array of length n
uint32_t max(uint32_t* arr, size_t n) {
	uint32_t max = 0;
	for (size_t i = 0; i < n; i++) {
		if (arr[i] > max) {
			max = arr[i];
		}
	}
	return max;
}

// returns the index of the first occurance of the maximum value of an array of length n
size_t max_idx(uint32_t* arr, size_t n) {
	size_t max_idx = 0;
	for (size_t i = 0; i < n; i++) {
		if (arr[i] > arr[max_idx]) {
			max_idx = i;
		}
	}
	return max_idx;
}

// return how often value j occurs in an array of length n
size_t card(uint32_t* arr, size_t n, uint32_t j) {
	size_t card = 0;
	for (size_t i = 0; i < n; i++) {
		if (arr[i] == j) {
			card++;
		}
	}
	return card;
}

// return the sum of all array elements
size_t sum(size_t* arr, size_t n) {
	size_t sum = 0;
	for (size_t i = 0; i < n; i++) {
		sum += arr[i];
	}
	return sum;
}

int main(int argc, char const *argv[]) {
	srand(time(NULL));
	// srand(0);
	
	// NUM_IT+1 counters. The counter i is increased if an attack was successful
	// after i iterations. The last counter, counter[NUM_IT], is increased when the
	// attack was unsuccessful.
	size_t results[NUM_IT] = { 0 };

	for (size_t experiment = 0; experiment < NUM_EXPERIMENTS; experiment++) {
		if (experiment % 10000 == 0)
			printf("Starting experiment %zu.\n", experiment);

		// Initialize success_ctr array to store per-key-hypothesis results
		// * 1st level: position
		// * 2nd level: leaked byte
		uint32_t success_ctr[AES128_KEY_SIZE][256] = {0};

		uint8_t key[AES128_KEY_SIZE];
		for (size_t pos = 0; pos < AES128_KEY_SIZE; pos++) {
			key[pos] = rand();
		}

		// Reserve memory to keep the key schedule
		uint8_t key_schedule[AES128_KEY_SCHEDULE_SIZE];
		
		// Pre-compute round keys (key schedule)
		aes128_key_schedule(key_schedule, key);

		// set up a memory region where aes-min will work in
		uint8_t block[AES128_KEY_SIZE];

		for (size_t it = 0; it < NUM_IT; it++) {
			// Generate random plaintext
			uint8_t plaintext[AES128_KEY_SIZE];
			for (int pos = 0; pos < AES128_KEY_SIZE; pos++) {
				plaintext[pos] = rand();
			}
			memcpy(block, plaintext, AES128_KEY_SIZE);

			// array to track the byte values that occur during the aes computation
			// at all positions
			uint8_t bytes_seen[AES128_KEY_SIZE][256] = { 0 };

			// Encrypt block using key schedule
			aes128_encrypt(block, key_schedule, bytes_seen);

			// For each of the 16 byte positions
			for (uint8_t pos = 0; pos < AES128_KEY_SIZE; pos++) {
				// For each possible value of a key byte
				for (uint16_t keyhyp = 0x00; keyhyp <= 0xff; keyhyp++) {
					// Pre-compute expected intermediate values at this position
					// for the given plain text and key hypothesis
					uint8_t afterAddRoundKey = plaintext[pos] ^ keyhyp;
					uint8_t afterSubBytes = aes_sbox(afterAddRoundKey);
					uint8_t afterShiftRowsIndex = sr_index_mapping[pos];

					// If both values were observed, increase the success_counter
					// of the key hypothesis byte value at the current position
					if ((1 == 1)
#if USE_AFTER_ADDROUNDKEY == 1
						&& (bytes_seen[pos][afterAddRoundKey] > 0)
#endif
#if USE_AFTER_SUBBYTES == 1
						&& (bytes_seen[pos][afterSubBytes] > 0)
#endif
#if USE_AFTER_SHIFTROWS == 1
						&& (bytes_seen[afterShiftRowsIndex][afterSubBytes] > 0)
#endif
					) {
						success_ctr[pos][keyhyp] += 1;
					}
				}
			}

			// check whether the most probable key hypothesis matches the
			// correct key
			int correct = 0;
			// for each position
			for (uint8_t pos = 0; pos < AES128_KEY_SIZE; pos++) {
				// the current key hypothesis is only correct if the following
				// conditions are fulfilled for all positions:
				//  * the maximum counter value in success_ctr[pos] is at index key[pos]
				//  * the maximum counter value appears only once in success_ctr[pos]
				if (!((max_idx(success_ctr[pos], 256) == key[pos])
					&& (card(success_ctr[pos], 256, max(success_ctr[pos], 256)) == 1))) {
					correct = 1;
					break;
				}
			}
			if (correct == 0) {
				results[it]++;
				break;
			}
		}
	}
	puts("Results:");
	for (size_t it = 0; it < NUM_IT; it++) {
		printf("Finished after %2zu plaintexts: %6zu\n", it+1, results[it]);
	}
	printf("Failed: %6zu\n", NUM_EXPERIMENTS - sum(results, NUM_IT));
}
