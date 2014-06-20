/*
 * src/test-asmalloc.c
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
 *    Test program for instrumenting using the ASMalloc memory allocation tracking tool.
 *    This program may be run either with or without the ASMalloc shared library preloaded
 *    via "LD_PRELOAD" feature, and may be built for use with either the GNU C Libary (GLibC)
 *    or JEMalloc supplying the the memory allocation functions.  It uses the fictitious
 *    database of memory allocation locations in the "test-mallocations.h" header file
 *    to simulate reporting of the program locations where the memory allocation-related
 *    functions are called.  (To instrument a real application, the mallocations database
 *    would be automatically generated from the application source code.)
 */

#define _GNU_SOURCE

#include <dlfcn.h>
#include <malloc.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "asmalloc.h"
#include "test-mallocations.h"

// Number of threads to spin up.
#define NUM_THREADS  (5)

// Number of iterations of the main loop to perform.
#define MAX_ITER  (10)

// Time to wait between hook invocations.
#define SLEEP_TIME (1)

// Maximum number of blocks of memory to allocate.
#define MAX_BLOCKS (1024)

// Maximum block size in bytes.
#define MAX_SIZE  (10 * 1000)

/*
 *  Default minimum size of blocks triggering mallocation alerts.
 */
#define DEFAULT_THRESH_BLOCK_SIZE_BYTES    (99990)

/*
 *  Default minimum delta size between mallocation alerts per thread.
 */
#define DEFAULT_THRESH_DELTA_SIZE_BYTES    (900 * 1024)

/*
 *  Default minimum time between mallocation alerts per thread.
 */
#define DEFAULT_THRESH_DELTA_TIME_SECONDS  (5)

/*
 *  Threshold for triggering memory allocation callbacks.
 */
size_t g_thresh_block_size = DEFAULT_THRESH_BLOCK_SIZE_BYTES;
size_t g_thresh_delta_size = DEFAULT_THRESH_DELTA_SIZE_BYTES;
time_t g_thresh_delta_time = DEFAULT_THRESH_DELTA_TIME_SECONDS;

// Is the program running?
bool g_running = false;

int original_hook(void *arg, asm_stats_t **asm_stats, vm_stats_t **vm_stats)
{
	fprintf(stderr, "In original_hook(%ld)!\n", (long) arg);
	fflush(stderr);

	return 0;
}

int (*g_hook)(void *arg, asm_stats_t **asm_stats, vm_stats_t **vm_stats) = original_hook;

int hook(void *arg, asm_stats_t **asm_stats, vm_stats_t **vm_stats)
{
	return (g_hook)(arg, asm_stats, vm_stats);
}

static int original_cmd(asm_cmd_t cmd, ...)
{
	fprintf(stderr, "In original_cmd(%d)!\n", cmd);
	fflush(stderr);

	return 0;
}

static int (*g_cmd)(asm_cmd_t cmd, ...) = original_cmd;

/*
 *  Invoke the command.
 */
int cmd(asm_cmd_t cmd, ...)
{
	va_list args;
	va_start(args, cmd);
	int retval = (g_cmd)(cmd, args);
	va_end(args);

	return retval;
}

void (*g_mallocation_set)(uint16_t type, uint16_t loc, ssize_t delta_size) = NULL;
void (*g_mallocation_get)(uint16_t *type, uint16_t loc, ssize_t *total_size, ssize_t *size) = NULL;

#ifdef FOR_JEMALLOC
void (*malloc_stats_print)(void (*write_cb)(void *, const char *), void *je_cbopaque, const char *opts) = NULL;
#endif

/*
 *  Type representing a unique location in the program where a memory allocation-related function is called.
 */
typedef uint16_t malloc_loc_t;

/*
 *  Register an immediately-upcoming memory allocation-related function on this thread.
 *
 *  Return 0 if successful, -1 otherwise.
 *
 *  XXX -- Do we have to do anything to guarantee this happens before the library function call?
 */
int mallocation_register(mallocation_type_t type, malloc_loc_t loc, ssize_t delta_size)
{
	int rv = -1;

	if (g_mallocation_set) {
		(g_mallocation_set)((uint16_t) type, (uint16_t) loc, delta_size);
		rv = 0;
	}

	return rv;
}

/*
 *  Callback function to log messages from the library.
 */
static void my_cb(uint64_t thread_id, uint16_t type, uint16_t loc, ssize_t delta_size, ssize_t total_size, struct timespec *last_time, void *udata)
{
	fprintf(stderr, "my_cb(): thread %lu ; type %d ; loc %d (%s:%d); delta_size %ld ; total_size %ld ; last_time %lu.%09lu\n",
			thread_id, type, loc, mallocations[loc].file, mallocations[loc].line, delta_size, total_size, last_time->tv_sec, last_time->tv_nsec);
}

void init(void)
{
	fprintf(stderr, "In init()!\n");
	fflush(stderr);

	if (!(g_hook = dlsym(RTLD_NEXT, "asm_hook"))) {
		g_hook = original_hook;
	}

	if (!(g_cmd = dlsym(RTLD_NEXT, "asm_cmd"))) {
		fprintf(stderr, "Could not find \"asm_cmd\" ~~ Using \"original_cmd\"!\n");
		g_cmd = original_cmd;
	}

	if (!(g_mallocation_set = dlsym(RTLD_NEXT, "asm_mallocation_set"))) {
		fprintf(stderr, "Could not find \"asm_mallocation_set\"!\n");
	}

	if (!(g_mallocation_get = dlsym(RTLD_NEXT, "asm_mallocation_get"))) {
		fprintf(stderr, "Could not find \"asm_mallocation_get\"!\n");
	}

#ifdef FOR_JEMALLOC
	if (!(malloc_stats_print = dlsym(RTLD_NEXT, "malloc_stats_print"))) {
		fprintf(stderr, "Could not find \"malloc_stats_print\"!\n");
	}
#endif

	cmd(ASM_CMD_SET_FEATURES, ASM_LOG_DATESTAMP | ASM_LOG_THREAD_STATS | ASM_LOG_MEM_COUNT_STATS | ASM_LOG_MALLOCATIONS | ASM_LOG_BLOCKS | ASM_LOG_MALLOC_INFO | ASM_LOG_MALLOC_STATS | ASM_LOG_MALLINFO | ASM_LOG_VM_STATS);
	cmd(ASM_CMD_SET_THRESHOLDS, g_thresh_block_size, g_thresh_delta_size, g_thresh_delta_time);
	cmd(ASM_CMD_SET_CALLBACK, my_cb, NULL);
}

void *thread_fn(void *arg)
{
	long id = (long) arg;
	int *blk[MAX_BLOCKS], blk_num = 0;
	bool wrapped = false;

	while (g_running) {
		size_t size = rand() % MAX_SIZE;
		malloc_loc_t loc = 3;

		mallocation_register(MALLOCATION_TYPE_MALLOC, loc, size);

		blk[blk_num++] = malloc(size);
		usleep(100);

		if (!(blk_num % 1000)) {
//			fprintf(stderr, "Thread #%ld: blk_num = %d\n", id, blk_num);
			fprintf(stderr, ".");
		}

		if (blk_num >= MAX_BLOCKS) {
			blk_num = 0;
			wrapped = true;
		}

		if (wrapped) {
			free(blk[blk_num]);
			blk[blk_num] = 0;
		}
	}

	int i;
	size_t total_size = 0;
	for (i = 0; i < MAX_BLOCKS; i++) {
		total_size += malloc_usable_size(blk[i]);
	}
	fprintf(stderr, "Thread #%ld:  Was using %ld bytes.\n", id, total_size);

	return 0;
}

int main(int argc, char *argv[])
{
	long i;
	int rv;
	pthread_t thread;

	if (((argc == 2) && !strcmp(argv[1], "--help")) || (argc > 4)) {
		fprintf(stderr, "Usage: %s [<ThreshBlockSize:default=%d bytes> <ThreshDeltaSize:default=%d bytes> <ThreshDeltaTime:default=%d seconds>\n",
				argv[0], DEFAULT_THRESH_BLOCK_SIZE_BYTES, DEFAULT_THRESH_DELTA_SIZE_BYTES, DEFAULT_THRESH_DELTA_TIME_SECONDS);
		fprintf(stderr, "\tPerform multi-threaded memory allocations test.\n");
		return -1;
	}
	if (argc > 1) {
		g_thresh_block_size = atol(argv[1]);
	} 
	if (argc > 2) {
		g_thresh_delta_size = atol(argv[2]);
	} 
	if (argc > 3) {
		g_thresh_delta_time = atol(argv[3]);
	}
	fprintf(stderr, "Test parameters:  g_thresh_block_size = %lu ; g_thresh_delta_size = %lu ; g_thresh_delta_time = %lu\n", g_thresh_block_size, g_thresh_delta_size, g_thresh_delta_time);

	init();

#ifdef FOR_JEMALLOC
	if (malloc_stats_print) {
		malloc_stats_print(NULL, NULL, NULL);
	}
#endif

	g_running = true;

	struct timespec ts;
	clock_gettime(CLOCK_REALTIME, &ts);
	srand(ts.tv_nsec % (1LU << 32));

	for (i = 0; i < NUM_THREADS; i++) {
		fprintf(stderr, "main():  Creating thread %ld\n", i);

		if ((rv = pthread_create(&thread, NULL, thread_fn, (void *) i))) {
			fprintf(stderr, "Failed to create thread #%ld!\n", i);
		}
	}

	long iter = 0;
	while (g_running) {
		asm_stats_t *asm_stats = NULL;
		vm_stats_t *vm_stats = NULL;

		hook((void *) iter, &asm_stats, &vm_stats);

		if (asm_stats) {
			fprintf(stderr, "***MAIN:  asm:  mem_count: %lu ; net_mmaps: %lu ; net_shm: %lu***\n",
					asm_stats->mem_count, asm_stats->net_mmaps, asm_stats->net_shm);
		}
		
		if (vm_stats) {
			vm_stats_desc_t *vm_stats_desc = vm_stats->desc;
			fprintf(stderr, "***MAIN:  vm:  %s: %lu KB; %s: %lu KB ; %s: %lu KB ; %s: %lu KB***\n",
					vm_stats_key_name(VM_PEAK),
					vm_stats_get_key_value(vm_stats, VM_PEAK), 
					vm_stats_key_name(VM_SIZE),
					vm_stats_get_key_value(vm_stats, VM_SIZE),
					vm_stats_key_name(VM_RSS),
					vm_stats_get_key_value(vm_stats, VM_RSS),
					vm_stats_key_name(VM_DATA),
					vm_stats_get_key_value(vm_stats, VM_DATA));
		}

		cmd(ASM_CMD_PRINT_STATS);

		if (++iter > MAX_ITER) {
			g_running = false;
		}
		sleep(SLEEP_TIME);
	}

	malloc_stats();

#ifdef FOR_JEMALLOC
	if (malloc_stats_print) {
		malloc_stats_print(NULL, NULL, NULL);
	}
#endif

	if ((rv = pthread_join(thread, NULL))) {
		fprintf(stderr, "Main failed to join thread %p with rv = %d!\n", (void *) thread, rv);
	}

	return 0;
}
