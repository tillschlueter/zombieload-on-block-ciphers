#ifndef DPA_VICTIM_UTILS_H
#define DPA_VICTIM_UTILS_H

#define _GNU_SOURCE // required by sched.h

#include <stdlib.h>
#include <sched.h>
#include <inttypes.h>

int move_process_to_cpu(pid_t pid, int cpu);

#endif