# ASMalloc: Memory Allocation Tracking

This repository provides a safe and efficient means to track dynamic
memory usage in programs using an implementation of the standard C
library **malloc(3)** / **free(3)** interface and is useful for locating
and eliminating memory leaks.

## Build

To build for use with GLibC (PTMalloc2):

    prompt% make

To build for use with JEMalloc:

    prompt% make jem

## Test

To test with GLibC:

    prompt% make test

To test with JEMalloc:

    prompt% make test.jem

## Clean

To clean GLibC {JEMalloc} build products:

    prompt% make clean{.jem}           -- Remove objects.

    prompt% make cleaner{.jem}         -- Remove the above plus programs.

    prompt% make cleanest{.jem}        -- Remove the above plus library.

## Application Integration

ASMalloc can be used to a very basic level without any modifications to
the application.  Using more advanced features requires integration of
the application with the ASMalloc API.

The output of ASMalloc will be logged to **stderr**.

To execute **my_executable** with ASMalloc, use the **LD_PRELOAD**
environment variable:

[*Note:*  Because they have slightly different needs, there are separate
builds for the GLibC-compatible (**lib/asmalloc.so**) and JEMalloc-compatible
(**lib/asmalloc.jem.so**) versions of the ASMalloc shared library.]

### With GLibC (PTMalloc2):

Under TCSH:

    prompt% env LD_PRELOAD=/path/to/asmalloc.so my_executable

Under BASH:

    prompt$ export LD_PRELOAD=/path/to/asmalloc.so my_executable

### With JEMalloc:

Under TCSH:

    prompt% env LD_PRELOAD=/path/to/asmalloc.jem.so:/path/to/libjemalloc.so my_executable

Under BASH:

    prompt$ export LD_PRELOAD=/path/to/asmalloc.jem.so:/path/to/libjemalloc.so my_executable

## ASMalloc API:

The ASMalloc API, declared in the file **include/asmalloc.h**, is as follows:

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

The following commands are available to be sent via **as_cmd()**:

    ASM_CMD_SET_FEATURES   -- Set the bit vector of ASMalloc features.
    ASM_CMD_SET_THRESHOLDS -- The the triplet of callback-triggering thresholds.
    ASM_CMD_SET_CALLBACK   -- Set the user's callback.
    ASM_CMD_PRINT_STATS    -- Print memory statistics.

The following independent features are available to be combined using
the bitwise OR operator ("|") and sent as the argument to the
**ASM_CMD_SET_FEATURES** command:

    ASM_LOG_DATESTAMP       -- Log the current date and time.
    ASM_LOG_THREAD_STATS    -- Log thread statistics.
    ASM_LOG_MEM_COUNT_STATS -- Log memory count statistics.
    ASM_LOG_MALLOCATIONS    -- Invoke callback on delta mallocations of sufficient size.
    ASM_LOG_BLOCKS          -- Invoke callback on block allocations of sufficient size.
    ASM_LOG_MALLOC_INFO     -- Log GLibC "malloc_info()" output.
    ASM_LOG_MALLOC_STATS    -- Log GLibC "malloc_stats()" output.
    ASM_LOG_MALLINFO        -- Log GLibC "mallinfo()" output.
    ASM_LOG_VM_STATS        -- Log the process' Virtual Memory (VM) statistics.

## Sample Application Integration:

Please see the **src/test-asmalloc.c** program for an example of how to
integrate an application with ASMalloc.

Note that the the file **include/test-mallocations.h** is sample database of
(fictitious) memory allocation function call locations in the
application.  This file defines types and a statically-initialized table
giving the info. about each memory allocation-related function call in
the application source code.  Ideally, the actual table would be
automatically re-generated whenever the application source code is modified.
