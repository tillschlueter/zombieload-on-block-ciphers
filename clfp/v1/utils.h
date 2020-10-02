#ifndef CLFP_UTILS_H
#define CLFP_UTILS_H

#define _GNU_SOURCE // required by sched.h

#include <stdio.h>
#include <stdlib.h>
#include <sched.h>
#include <inttypes.h>
#include <string.h>

#include "aes-min/aes-min.h"
#include "main.h"

int move_process_to_cpu(pid_t pid, int cpu);
void print_aes_key(uint8_t* c);
int compare_hist_elem_by_count_desc(const void* a, const void* b);
int check_pair_oneway(uint8_t* rk1, uint8_t* rk2);
int check_pair(uint8_t* rk1, uint8_t* rk2);

#endif