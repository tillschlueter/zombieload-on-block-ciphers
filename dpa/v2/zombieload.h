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

void zombieload_collect_samples_v2();
void recover(uint8_t pos);
void zombieload_sample_v2(size_t pos, size_t num_repetitions);
pid_t start_victim_process();

#endif