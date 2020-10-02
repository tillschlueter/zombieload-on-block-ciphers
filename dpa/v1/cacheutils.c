/*
 * Based on
 *   https://github.com/IAIK/ZombieLoad/blob/bcd9c99d5c9164d23d45de584c63a8c92c6662d5/attacker/variant1_linux/cacheutils.h
 */

#include "cacheutils.h"

jmp_buf trycatch_buf;

// ---------------------------------------------------------------------------
// Measure access time to ptr and flush ptr afterwards.
// Return Value:
//   0: cache miss
//   1: cache hit
int flush_reload(void *ptr, size_t threshold) {
	uint64_t start = 0, end = 0;

	// Get timestamp counter before memory access
#if USE_RDTSC_BEGIN_END
	start = rdtsc_begin();
#else
	start = rdtsc();
#endif

	// Perform memory access to ptr
	maccess(ptr);

	// Get timestamp counter after memory access
#if USE_RDTSC_BEGIN_END
	end = rdtsc_end();
#else
	end = rdtsc();
#endif

	// finish all pending memory operations
	mfence();

	// flush ptr from cache
	flush(ptr);

	// cache hit?
	if (end - start < threshold) {
		return 1;
	}
	// cache miss
	return 0;
}

// ---------------------------------------------------------------------------
// Measure access time to ptr and flush ptr afterwards.
// Return Value:
//   Elapsed Time Stamp Counter difference
int flush_reload_t(void *ptr) {
	uint64_t start = 0, end = 0;

	// Get timestamp counter before memory access
#if USE_RDTSC_BEGIN_END
	start = rdtsc_begin();
#else
	start = rdtsc();
#endif

	// Perform memory access to ptr
	maccess(ptr);

	// Get timestamp counter after memory access
#if USE_RDTSC_BEGIN_END
	end = rdtsc_end();
#else
	end = rdtsc();
#endif

	// finish all pending memory operations
	mfence();

	// flush ptr from cache
	flush(ptr);

	// return elapsed TSC difference
	return (int)(end - start);
}

// ---------------------------------------------------------------------------
// Measure access time to ptr. DON'T flush ptr afterwards.
// Return Value:
//   Elapsed Time Stamp Counter difference
int reload_t(void *ptr) {
	uint64_t start = 0, end = 0;

	// Get timestamp counter after before memory access
#if USE_RDTSC_BEGIN_END
	start = rdtsc_begin();
#else
	start = rdtsc();
#endif

	// Perform memory access to ptr
	maccess(ptr);

	// Get timestamp counter after memory access
#if USE_RDTSC_BEGIN_END
	end = rdtsc_end();
#else
	end = rdtsc();
#endif

	// finish all pending memory operations
	mfence();

	// return elapsed TSC difference
	return (int)(end - start);
}


// ---------------------------------------------------------------------------
// Detect Threshold for Flush+Reload-Attack
// Return Value:
//   Threshold (in TSC ticks)
size_t detect_flush_reload_threshold() {
	size_t reload_time = 0, flush_reload_time = 0, i, count = 1000000;
	size_t dummy[16];
	size_t *ptr = dummy + 8;

	// access ptr for the first time. ptr will be cached.
	maccess(ptr);

	// access ptr count more times. All requests should be answered from cache
	// and therefore be fast. Cumulate the duration of all accesses.
	for (i = 0; i < count; i++) {
		reload_time += reload_t(ptr);
	}
	// access ptr count more times, but flush it from cache after every access.
	// These accesses should all be slow. Cumulate the durations.
	for (i = 0; i < count; i++) {
		flush_reload_time += flush_reload_t(ptr);
	}
	// Calculate averages
	reload_time /= count;
	flush_reload_time /= count;

	// Calculate threshold
	return (flush_reload_time + reload_time * 2) / 3;
}


// ---------------------------------------------------------------------------
// Get physical address from virtual address
// Return Value:
//   physical address
size_t get_physical_address(size_t vaddr) {
	// vaddr is composed of 2 parts:
	//  * virtual page number (upper bits)
	//  * offset inside the page (12 least significant bits)

	// 1st step: Find the physical page (page frame) number corresponding
	//           to the given virtual page number

	// Open virtual file /proc/self/pagemap
	int fd = open("/proc/self/pagemap", O_RDONLY);
	uint64_t virtual_addr = (uint64_t)vaddr;
	size_t value = 0;

	// Calculate offset to read from
	off_t offset = (virtual_addr / 4096) * sizeof(value);
	
	// Read from fd at offset into value
	int got = pread(fd, &value, sizeof(value), offset);
	// Read failed?
	if(got != sizeof(value)) {
		return 0;
	}

	// Close file handle
	close(fd);

	// value contains the page frame number.

	// 2nd step: Compose physical address:
	//  * Shift page frame number by 12 bits to the left.
	//  * Copy the 12 LSB from vaddr into the return value.
	return (value << 12) | ((size_t)vaddr & 0xFFFULL);
}

// ---------------------------------------------------------------------------
// Returns the base address of the direct-physical map.
size_t get_direct_physical_map() {
	// Query Linux Kernel Version
	struct utsname buf;
	uname(&buf);
	// Major version number
	int major = atoi(strtok(buf.release, "."));
	// Minor version number
	int minor = atoi(strtok(NULL, "."));
	
	if((major == 4 && minor < 19) || major < 4) {
		// Base address for kernel versions < 4.19
		return 0xffff880000000000ull;
	} else {
		// Base address for kernel versions >= 4.19
		return 0xffff888000000000ull;
	}
}

// ---------------------------------------------------------------------------
// Helper function to unblock a signal
void unblock_signal(int signum __attribute__((__unused__))) {
	sigset_t sigs;
	sigemptyset(&sigs);
	sigaddset(&sigs, signum);
	sigprocmask(SIG_UNBLOCK, &sigs, NULL);
}

// ---------------------------------------------------------------------------
// Signal Handler to handle the SIGSEGV signal after illegal memory accesses.
void trycatch_segfault_handler(int signum) {
	// Ignore value of signum (prevents "unused parameter" warnings)
	(void)signum;
	// Unblock signals. Signals are normally blocked until this handler function
	// returns. We unblock them manually (to allow other signals to arrive while
	// the handler runs?).
	unblock_signal(SIGSEGV);
	unblock_signal(SIGFPE);
	// Jump back to setjmp(). setjmp() will return 1.
	longjmp(trycatch_buf, 1);
}