#ifndef DPA_UTILS_H
#define DPA_UTILS_H

#define _GNU_SOURCE // required by sched.h

#include <stdio.h>
#include <stdlib.h>
#include <sched.h>
#include <inttypes.h>
#include <string.h>

#include "main.h"

int move_process_to_cpu(pid_t pid, int cpu);
int compare_success_ctr_elem_by_count_desc(const void* a, const void* b);
uint32_t* access_hist(uint32_t* hist, size_t ptid, size_t pos, size_t byte);
void print_aes_key(uint8_t* c);

#endif