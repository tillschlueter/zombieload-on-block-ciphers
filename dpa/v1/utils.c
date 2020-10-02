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

// Comparison function to compare success_ctr_elems by conut in descending order.
// If both elements have the same count, the lower byte value wins.
int compare_success_ctr_elem_by_count_desc(const void* a, const void* b) {
	success_ctr_elem* sce_a = (success_ctr_elem*)a;
	success_ctr_elem* sce_b = (success_ctr_elem*)b;
	if (sce_b->count != sce_a->count) {
		return sce_b->count - sce_a->count;
	} else {
		return sce_a->byte - sce_b->byte;
	}
}

// from main
extern size_t num_plaintexts;

// helper function to access 3D array "hist" on heap
uint32_t* access_hist(uint32_t* hist, size_t ptid, size_t pos, size_t byte) {
	return hist
		+ ptid
		+ num_plaintexts * pos
		+ num_plaintexts * NUM_POSITIONS * byte;
}

void print_aes_key(uint8_t* c) {
	for (size_t i = 0; i < KEY_LENGTH; i++) {
		printf("%.2x ", *(c+i));
	}
	puts("");
}