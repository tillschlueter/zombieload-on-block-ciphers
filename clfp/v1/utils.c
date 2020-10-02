#include "utils.h"

// Helper function that returns a cpu_set_t with a cpu affinity mask
// that limits execution to the single (logical) CPU core cpu.
cpu_set_t build_cpuset(int cpu) {
	cpu_set_t cpuset;
	CPU_ZERO(&cpuset);
	CPU_SET(cpu, &cpuset);
	return cpuset;
}

// Set affinity mask of the given process so that the process is executed
// on a specific (logical) core.
int move_process_to_cpu(pid_t pid, int cpu) {
	cpu_set_t cpuset = build_cpuset(cpu);
	return sched_setaffinity(pid, sizeof(cpu_set_t), &cpuset);
}

void print_aes_key(uint8_t* c) {
	for (size_t i = 0; i < KEY_LENGTH; i++) {
		printf("%.2x ", *(c+i));
	}
	puts("");
}

// Comparison function to compare histelems by conut in descending order.
int compare_hist_elem_by_count_desc(const void* a, const void* b) {
	return ((hist_elem*)b)->count - ((hist_elem*)a)->count;
}

// AES128 key schedule round constants
const uint8_t rcon[] = {
	1, 2, 4, 8, 16, 32, 64, 128, 27, 54
};

// Does Round Key rk2 appear before rk1 in an AES128 key schedule?
// If so, rk1, rk2, and the initial key are printed to stdout.
// Return value >  0: yes.
// Return value = -1: no.
int check_pair_oneway(uint8_t* rk1, uint8_t* rk2) {
	uint8_t tmp[KEY_LENGTH];

	// for each rk1 round assumption
	for (int round = 1; round < 10; round++) {
		// assume rk1 was a round key from round no. 'round'
		// create a temporary copy of rk1 to work with
		memcpy(tmp, rk1, KEY_LENGTH);

		// roll back rk1 one round at a time and compare the result to rk2
		for (int offset = 1; offset <= round; offset++) {
			// calculate the previous round key
			aes128_key_schedule_inv_round(tmp, rcon[round-offset]);

			// compare: is rk2 the previous round key?
			if (memcmp(tmp, rk2, KEY_LENGTH) == 0) {
				// it's a match! return offset.
				printf("The round key\n\t");
				print_aes_key(rk1);
				printf("is from round %u. The key\n\t", round);
				print_aes_key(rk2);
				printf("occurs %u rounds before in round %u. Your AES128 key (round key 0) is:\n\t", offset, round-offset);
				for (int i = 1; i <= round-offset; i++) {
					aes128_key_schedule_inv_round(tmp, rcon[round-offset-i]);
				}
				print_aes_key(tmp);
				return offset;
			}
		}
	}
	return -1;
}

// Do the round keys rk1 and rk2 appear in the same AES128 key schedule?
int check_pair(uint8_t* rk1, uint8_t* rk2) {
	int res1 = check_pair_oneway(rk1, rk2);
	if (res1 >= 0) {
		return res1;
	} else {
		return check_pair_oneway(rk2, rk1);
	}
}