/*
 * include/vm_stats.h
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
 *    Declarations file for the Virtual Memory (VM) statistics functions of
 *    the ASMalloc memory allocation tracking tool.  These types and functions
 *    are used both internally by ASMalloc and by the program being instrumented.
 */

#pragma once

#include <stdint.h>

/*
 *  Type representing a key name string and its offset in the "vm_stats_t" object.
 */
typedef struct vm_stats_desc_s {
	char *name;
	size_t offset;
} vm_stats_desc_t;

/*
 *  Array of VM-related key names and structure offsets.
 */
extern vm_stats_desc_t vm_stats_desc[];

/*
 *  Type representing the Virtual Memory (VM)-related statistics about a process.
 *
 *  Note:  Not all of these will exist on all versions of the Linux kernel, so
 *          UINT64_MAX is used to indicate a non-existent value.
 *
 *  Also Note:  All of these related types must be kept in sync.!
 */
typedef struct vm_stats_s {
	vm_stats_desc_t *desc; // Description of the VM stats structure.
	uint64_t
		vm_peak,        // Peak Virtual Set Size in KB.
		vm_size,        // Current Virtual Set Size in KB.
		vm_lck,         // Current "mlock(2)"'d memory size in KB.
		vm_pin,         // Current pinned (unswappable) memory size in KB.  [In 3.2+ kernels.]
		vm_hwm,         // Peak Resident Set Size in KB.
		vm_rss,         // Current Resident Set Size in KB.
		vm_data,        // Size of "data" segment in KB.
		vm_stk,         // Size of stack in KB.
		vm_exe,         // Size of "text" segment in KB.
		vm_lib,         // Shared library size (all pages, not just used ones!)
		vm_pte,         // Size of Page Table Entries in KB.
		vm_swap;        // Swap space used size in KB.                      [In 2.6.34+ kernels.]
} vm_stats_t;

/*
 *  Symbolic key names for the VM-related statistics, corresponding to the position in the "vm_stats_desc[]" array.
 */
typedef enum vm_stats_key_e {
	VM_PEAK,
	VM_SIZE,
	VM_LCK,
	VM_PIN,
	VM_HWM,
	VM_RSS,
	VM_DATA,
	VM_STK,
	VM_EXE,
	VM_LIB,
	VM_PTE,
	VM_SWAP,
	VM_NUM_KEYS
} vm_stats_key_t;

/*
 *  Return the name for the given key.
 */
#define vm_stats_key_name(key) (vm_stats_desc[key].name)

/*
 *  Return the value for the VM statistic with the given key.
 */
#define vm_stats_get_key_value(vm_stats_tp, key) (* (uint64_t *)(((char *) vm_stats_tp) + vm_stats_desc[key].offset))

/*
 *  Set the value for the VM statistic with the given key to the given value.
 */
#define vm_stats_set_key_value(vm_stats_tp, key, val) ((* (uint64_t *)(((char *) vm_stats_tp) + vm_stats_desc[key].offset)) = (val))

/*
 *  Read the kernel's VM-related statistics for process PID into the given structure.
 */
int get_vm_stats(int pid, vm_stats_t *stats);

/*
 *  Print the current VM-related statistics for the given PID.
 */
vm_stats_t *log_vm_stats(int pid);
