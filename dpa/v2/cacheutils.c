/*
 * Based on
 *   https://github.com/IAIK/ZombieLoad/blob/bcd9c99d5c9164d23d45de584c63a8c92c6662d5/attacker/variant1_linux/cacheutils.h
 *   https://github.com/IAIK/ZombieLoad/blob/9f6e3a553f63aee21f5f80dda75ed6308f12b7da/attacker/variant2_linux_windows/cacheutils.h
 */

#include "cacheutils.h"

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
// Check TSX availability
// Returns 1 if available, 0 otherwise.
int has_tsx() {
	if (__get_cpuid_max(0, NULL) >= 7) {
		unsigned a, b, c, d;
		__cpuid_count(7, 0, a, b, c, d);
		return (b & (1 << 11)) ? 1 : 0;
	} else {
		return 0;
	}
}
