#ifndef ZOMBIELOAD_H
#define ZOMBIELOAD_H

#define _GNU_SOURCE // required by sched.h

#include <stdio.h>
#include <stdlib.h>
#include <sched.h>
#include <string.h>
#include <sys/mman.h>

#include "main.h"
#include "utils.h"
#include "cacheutils.h"

typedef struct {
	uint8_t* mapping;
	uint8_t* target;
} zombieload_mapping;

void zombieload_collect_samples_v1();
void recover(uint8_t pos);
zombieload_mapping create_mapping();
void destroy_mapping(zombieload_mapping m);
void zombieload_sample_v1(zombieload_mapping m, size_t register pos, size_t num_repetitions);
pid_t start_victim_process();

#endif