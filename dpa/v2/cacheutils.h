/*
 * Based on 
 *   https://github.com/IAIK/ZombieLoad/blob/bcd9c99d5c9164d23d45de584c63a8c92c6662d5/attacker/variant1_linux/cacheutils.h
 *   https://github.com/IAIK/ZombieLoad/blob/9f6e3a553f63aee21f5f80dda75ed6308f12b7da/attacker/variant2_linux_windows/cacheutils.h
 */

#ifndef _CACHEUTILS_H_
#define _CACHEUTILS_H_

// pread() requires this:
#ifndef _XOPEN_SOURCE
#define _XOPEN_SOURCE 500
#endif

#include <stdio.h>
#include <stdint.h>
#include <cpuid.h>

/* ============================================================
 *                    User configuration
 * ============================================================ */
// size_t CACHE_MISS = 150;

#define USE_RDTSC_BEGIN_END     0

#define USE_RDTSCP              1

/* ============================================================
 *                  User configuration End
 * ============================================================ */

// ---------------------------------------------------------------------------
// Returns current CPU Time Stamp Counter (TSC).
static inline __attribute__((always_inline)) uint64_t rdtsc() {
	uint64_t a, d;
	__asm__ volatile("mfence");
#if USE_RDTSCP
	__asm__ volatile("rdtscp" : "=a"(a), "=d"(d) :: "rcx");
#else
	__asm__ volatile("rdtsc" : "=a"(a), "=d"(d));
#endif
	a = (d << 32) | a;
	__asm__ volatile("mfence");
	return a;
}

// ---------------------------------------------------------------------------
// Flush cache line containing p
static inline __attribute__((always_inline)) void flush(void *p) {
	__asm__ volatile("clflush 0(%0)\n" : : "c"(p) : "rax");
}

// ---------------------------------------------------------------------------
// Access memory address p (move to register)
static inline __attribute__((always_inline)) void maccess(void *p) {
	__asm__ volatile("movq (%0), %%rax\n" : : "c"(p) : "rax");
}

// ---------------------------------------------------------------------------
// Performs a serializing operation on all load-from-memory and store-to-memory
// instructions that were issued prior the MFENCE instruction. This serializing
// operation guarantees that every load and store instruction that precedes
// the MFENCE instruction in program order becomes globally visible before any
// load or store instruction that follows the MFENCE instruction. (intel-sdm-v2)
static inline __attribute__((always_inline)) void mfence() {
	__asm__ volatile("mfence");
}

// ---------------------------------------------------------------------------
// Begin TSX region
static inline __attribute__((always_inline)) unsigned int xbegin() {
	unsigned status;
	asm volatile(".byte 0xc7,0xf8,0x00,0x00,0x00,0x00" : "=a"(status) : "a"(-1UL) : "memory");
	return status;
}

// ---------------------------------------------------------------------------
// End TSX region
static inline __attribute__((always_inline)) void xend() {
	asm volatile(".byte 0x0f; .byte 0x01; .byte 0xd5" ::: "memory");
}

int flush_reload(void *ptr, size_t threshold);
int flush_reload_t(void *ptr);
int reload_t(void *ptr);
size_t detect_flush_reload_threshold();
int has_tsx();

#endif
