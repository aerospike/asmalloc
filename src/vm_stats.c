/*
 * src/vm_stats.c
 *
 * Copyright (C) 2013-2014 Aerospike, Inc.
 *
 * Portions may be licensed to Aerospike, Inc. under one or more contributor
 * license agreements.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy of
 * the License at http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under
 * the License.
 */

/*
 *  SYNOPSIS
 *    Determine the Virtual Memory (VM) statistics for a given process
 *    by reading the process' "/proc/<PID>/status" file.  This code has
 *    been verified under Linux kernel versions from 2.6.X ==> 3.2.X.
 *    Future kernel versions may provide additional VM statistics that
 *    may be worthwhile to add to the set this module knows about.
 *    This is part of the ASMalloc memory allocation tracking tool.
 */

#include <ctype.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "vm_stats.h"

/*
 *  Array of VM-related key names and structure offsets.
 */
vm_stats_desc_t vm_stats_desc[] =
{
	{ "VmPeak", offsetof(vm_stats_t, vm_peak) },
	{ "VmSize", offsetof(vm_stats_t, vm_size) },
	{ "VmLck",  offsetof(vm_stats_t, vm_lck)  },
	{ "VmPin",  offsetof(vm_stats_t, vm_pin)  },
	{ "VmHWM",  offsetof(vm_stats_t, vm_hwm)  },
	{ "VmRSS",  offsetof(vm_stats_t, vm_rss)  },
	{ "VmData", offsetof(vm_stats_t, vm_data) },
	{ "VmStk",  offsetof(vm_stats_t, vm_stk)  },
	{ "VmExe",  offsetof(vm_stats_t, vm_exe)  },
	{ "VmLib",  offsetof(vm_stats_t, vm_lib)  },
	{ "VmPTE",  offsetof(vm_stats_t, vm_pte)  },
	{ "VmSwap", offsetof(vm_stats_t, vm_swap) }
};

/*
 *  Return a (statically-allocated) string representation of the current date and time.
 *
 *  +++NOTE:  This function must NOT allocate memory!+++
 */
static char *datestamp()
{
	static char datestamp[100];

	time_t now = time(NULL);
	strftime(datestamp, sizeof(datestamp), "%d %B %Y @ %H:%M:%S", localtime(&now));

	return datestamp;
}

/*
 *  Read a single key from the given buffer and set the appropriate numeric value in stats.
 *
 *  NOTE:  This code assumes that the given key is at the current position in the buffer,
 *          which is generally the case, or else the statistic is not provided by this version
 *          of the kernel, since the ordering tends to remain consistent across kernel versions.
 *          (A less efficient, but more robust, approach would be to scan the entire buffer each time.)
 *
 *  +++NOTE:  This function must NOT allocate memory!+++
 */
static uint64_t read_key(int key, vm_stats_t *stats, char **buf)
{
	uint64_t val = 0;
	bool found_val = false;

	char *kp = vm_stats_key_name(key);
	char *bp = *buf;
	while (*kp && *bp && (*kp++ == *bp++))
	  ;

	if (*kp) {
		// XXX -- This is not actually the correct error message for this case.
//		fprintf(stderr, "Failed to read expected \"%s\" ~~ found \"%s\"\n", vm_stats_key_name(key), *buf);
		return UINT64_MAX;
	}

	while (*bp && !isdigit(*bp))
	  bp++;

	while (*bp && isdigit(*bp)) {
		found_val = true;
		if (val)
		  val *= 10;
		val += *bp++ - '0';
	}

	while (*bp && '\n' != *bp++)
	  ;

	*buf = bp;

	if (found_val)
	  vm_stats_set_key_value(stats, key, val);

	return val;
}

/*
 *  Read the kernel's VM-related statistics for process PID into the given structure.
 */
int get_vm_stats(int pid, vm_stats_t *stats)
{
	static int fd = -1;
	static int saved_pid = -1;

	if ((-1 == fd) || (pid != saved_pid)) {
		char stat_filename[100];
		sprintf(stat_filename, "/proc/%d/status", pid);

		if (-1 != fd)
		  close(fd);

		if (0 > (fd = open(stat_filename, O_RDONLY))) {
			perror("open");
			return -1;
		}

		saved_pid = pid;
	} else {
		lseek(fd, 0, SEEK_SET);		
	}

	char buf[1024];
	int num_read = read(fd, buf, sizeof(buf));

	if (0 > num_read) {
		perror("read");
		close(fd);
		return -1;
	}

	// Note:  Assume certain ordering for the fields ~~ Kernel interface dependent!
	int pos = 0;
	bool line_start = true;
	while (pos < num_read) {
		if ('\n' == buf[pos])
		  line_start = true;
		else if (line_start && ('V' == buf[pos]))
		  break;
		else
		  line_start = false;
		pos++;
	}

	if (pos >= num_read) {
		fprintf(stderr, "Could not locate 'V' after reading %d characters!\n", pos);
		close(fd);
		return saved_pid = fd = -1;
	}

	char *bp = &buf[pos];
	for (int key = 0; key < VM_NUM_KEYS; key++)
	  read_key(key, stats, &bp);

	return 0;
}

/*
 *  Print a VM-related statistic if it exists.
 *
 *  +++NOTE:  This function must NOT allocate memory!+++
 */
static void print_if_found(int key, vm_stats_t *stats)
{
	uint64_t val;

	if (UINT64_MAX != (val = vm_stats_get_key_value(stats, key)))
	  fprintf(stderr, "   %s = %lu\n", vm_stats_key_name(key), val);
}

/*
 *  Print the current VM-related statistics for the given PID.
 *
 *  +++NOTE:  This function must NOT allocate memory!+++
 */
vm_stats_t *log_vm_stats(int pid)
{
	static int64_t init_size = 0;
	static int64_t last_size = 0;
	static vm_stats_t stats;

	// Initialize all statistics to not found the first time around.
	if (!init_size) {
		// Initialize the description of the VM stats structure.
		stats.desc = &vm_stats_desc[0];

		for (int key = 0; key < VM_NUM_KEYS; key++)
		  vm_stats_set_key_value(&stats, key, UINT64_MAX);
	}

	if (-1 == get_vm_stats(pid, &stats)) {
		fprintf(stderr, "Failed to get VM stats for PID %d!\n", pid);
		return 0;
	}

	if (0 >= init_size) {
		init_size = stats.vm_size;
	}

	int64_t delta = stats.vm_size - last_size;
	int64_t net_delta = stats.vm_size - init_size;

	if (delta) {
		fprintf(stderr, "\n%s:  Proc %d %s by %ld KB (net change: %ld KB)\n", datestamp(), pid, (delta ? (delta > 0 ? "grew" : "shrunk") : "unchanged"), delta, net_delta);
		last_size = stats.vm_size;
		for (int key = 0; key < VM_NUM_KEYS; key++)
		  print_if_found(key, &stats);
	}

	return &stats;
}
