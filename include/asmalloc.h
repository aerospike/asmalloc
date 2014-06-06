/*
 * include/asmalloc.h
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
 *    Declarations file for the ASMalloc memory allocation tracking tool.
 *    This header file provides the external API to ASMalloc for use by
 *    the program being instrumented.
 */

#pragma once

#include <stdarg.h>
#include <stdint.h>
#include <time.h>
#include <unistd.h>

#include "vm_stats.h"

/*
 *  Bit vector flags for enabling ASMalloc features.
 *  (Logging happens in the hook function.)
 */
typedef enum asm_features_e {
	ASM_LOG_DATESTAMP       = (1 << 0),  // Log the current date and time.
	ASM_LOG_THREAD_STATS    = (1 << 1),  // Log thread statistics.
	ASM_LOG_MEM_COUNT_STATS = (1 << 2),  // Log memory count statistics.
	ASM_LOG_MALLOCATIONS    = (1 << 3),  // Invoke callback on delta mallocations of sufficient size.
	ASM_LOG_BLOCKS          = (1 << 4),  // Invoke callback on block allocations of sufficient size.
	ASM_LOG_MALLOC_INFO     = (1 << 5),  // Log GLibC "malloc_info()" output.
	ASM_LOG_MALLOC_STATS    = (1 << 6),  // Log GLibC "malloc_stats()" output.
	ASM_LOG_MALLINFO        = (1 << 7),  // Log GLibC "mallinfo()" output.
	ASM_LOG_VM_STATS        = (1 << 8)   // Log the process' Virtual Memory (VM) statistics.
} asm_features_t;

/*
 *  Type for memory accounting commands.
 */
typedef enum asm_cmd_e {
	ASM_CMD_SET_FEATURES,                // Set the bit vector of ASMalloc features.
	ASM_CMD_SET_THRESHOLDS,              // The the triplet of callback-triggering thresholds.
	ASM_CMD_SET_CALLBACK,                // Set the user's callback.
	ASM_CMD_PRINT_STATS                  // Print memory statistics.
} asm_cmd_t;

/*
 *  Type for the memory statistics, all in bytes.
 */
typedef struct asm_stats_s {
	size_t mem_count;                    // Net dynamic memory allocated by the process.
	size_t net_mmaps;                    // Net memory "mmap(2)"'d by the process.
	size_t net_shm;                      // Net Sys V shared memory held by the process.
} asm_stats_t;

/*
 *  Library-exported version of the hook function.
 */
int asm_hook(void *arg, asm_stats_t **asm_stats, vm_stats_t **vm_stats);

/*
 *  Library-exported version of the command function.
 */
int asm_cmd(asm_cmd_t cmd, va_list args);

/*
 *  Store the type and location of a mallocation in thread-specific storage.
 */
void asm_mallocation_set(uint16_t type, uint16_t loc, ssize_t delta_size);

/*
 *  Return the type and location of a mallocation in thread-specific storage.
 */
void asm_mallocation_get(uint16_t *type, uint16_t loc, ssize_t *total_size, ssize_t *delta_size, struct timespec *last_time);
