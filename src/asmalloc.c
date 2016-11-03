/*
 * src/asmalloc.c
 *
 * Copyright (C) 2013-2016 Aerospike, Inc.
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
 *    ASMalloc is a memory allocation tracking tool with extremely low overhead,
 *    suitable for use on multi-threaded, high-performance, high-memory-use systems.
 *    The tool is embodied in a dynamic shared library used via "LD_PRELOAD".  It
 *    provids wrapper functions for the standard C library memory allocation-related
 *    function plus the control APIs necessary for performing memory allocation tracking.
 */

#define _GNU_SOURCE

#include <dlfcn.h>
#include <errno.h>
#include <malloc.h>
#include <math.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/ipc.h>
#include <sys/shm.h>

#include "asmalloc.h"

/*
 *  Small buffer to handle "calloc()" calls in "libdl" at startup time.
 */
#define  HAKBUF_SIZE  (1024)
static char hakbuf[HAKBUF_SIZE];
static char *hakbuf_ptr = hakbuf;
static size_t haksize = sizeof(hakbuf);

/*
 *  Enable debug printouts.
 */
//#define DEBUG

/*
 *  Define macro to control printouts
 */
#ifdef DEBUG
#define dfprintf  fprintf
#define dfputs    fputs
#else
#define dfprintf  if (false) fprintf
#define dfputs    if (false) fputs
#endif

/*
 *  Log a single character.
 */
#define LOG(c) { putchar(c); putchar('\n'); fflush(stdout); }

/*
 *  Log two characters.
 */
#define LOG2(c, d) { putchar(c); putchar(d); putchar('\n'); fflush(stdout); }

/*
 *  Break into the debugger if the "BREAK" environment variable is set.
 */
#define BREAK() if (getenv("BREAK")) { __asm__("int3"); }

/*
 *  Macro to initialize us only once.
 */
#define INIT(x) if (!inited) { if (x <= 1) { init(x); } }

/*
 *  Are any of the given features enabled?
 */
#define FEATURE(x) (g_features & (x))

/*
 *  Are all of (and only) the given features enabled?
 */
#define FEATURES(x) ((g_features & (x)) & ~(g_features & ~(x)))

/*
 *  Default features to enable.
 */
#define DEFAULT_FEATURES (ASM_LOG_DATESTAMP | ASM_LOG_THREAD_STATS | ASM_LOG_MEM_COUNT_STATS | ASM_LOG_MALLOCATIONS | ASM_LOG_BLOCKS | ASM_LOG_VM_STATS)

/*
 *  Features currently enabled.
 */
static uint64_t g_features = DEFAULT_FEATURES;

/*
 *  Maximum number of unique memory allocation program locations.
 *
 *  [Note:  This is used to size the allocation thread-specific data.]
 *
 *  ***WARNING:  Bad things will happen if this number is exceeded by the program!!***
 */
#define MAX_TLS_MALLOCATIONS (1152)

/*
 *  Default minimum size of blocks triggering mallocation alerts.
 */
#define DEFAULT_THRESH_BLOCK_SIZE_BYTES    (512 * 1024)

/*
 *  Default minimum delta size between mallocation alerts per thread.
 */
#define DEFAULT_THRESH_DELTA_SIZE_BYTES    (1024 * 1024)

/*
 *  Default minimum time between mallocation alerts per thread.
 */
#define DEFAULT_THRESH_DELTA_TIME_SECONDS  (60)

/*
 *  Threshold for triggering memory allocation callbacks.
 */
static size_t g_thresh_block_size = DEFAULT_THRESH_BLOCK_SIZE_BYTES;
static size_t g_thresh_delta_size = DEFAULT_THRESH_DELTA_SIZE_BYTES;
static time_t g_thresh_delta_time = DEFAULT_THRESH_DELTA_TIME_SECONDS;

/*
 *  Type encapsulating all of the necessary state for a thread to be created.
 *
 *  This value is passed to "asm_start_routine()" to wrap the user's thread start
 *  routine with the extra steps we need to perform on every thread (i.e., creating
 *  the thread-specific data.
 */
typedef struct asm_thread_launcher_s {
	uint64_t id;                         // Our ID for this thread.
	void *(*start_routine)(void *);      // User's thread start routine.
	void *arg;                           // User's thread start routine argument.
	const char *sname;                   // Name of start routine.
} asm_thread_launcher_t;

/*
 *  Type for distinguishing allocations from frees.
 */
typedef enum alloc_or_free_e {
	ALLOC = 0,                            // Any memory-allocting operation.
	FREE = 1                              // Any memory-freeing operation.
} alloc_or_free_t;

/*
 *  Location where the mallocation "loc" of the memory allocation is located
 *   (i.e., the last "int" in usable size of the memory block.)
 */
#define LOC_LOC(ptr) ((int *) (((char *) ptr) + malloc_usable_size(ptr) - sizeof(int)))
// XXX -- An alternative way.
//#define LOC_LOC(ptr) ((int *) (((char *) ptr) + actual_size - sizeof(int)))

/*
 *  Set the "loc" of the mallocation at the end of the memory block.
 */	
#if 0
#define SET_LOC_LOC(ptr)												\
	if (type && tls_mallocation_ptr) {									\
		ssize_t dds = actual_size - delta_size;							\
		tls_mallocation_ptr->total_size += (actual_size - delta_size);	\
		if (dds < 0)													\
		  fprintf(stderr, "sll(): type = %d ; loc = %d ; as = %ld ; ds = %ld ; dds = %ld\n", type, loc, actual_size, delta_size, actual_size - delta_size); \
		*LOC_LOC(ptr) = tls_mallocations[0].loc;						\
	}
#elif 0
#define SET_LOC_LOC(ptr)												\
	if (type && tls_mallocation_ptr) {									\
		ssize_t dds = actual_size - size;								\
		tls_mallocation_ptr->total_size += (actual_size - size);		\
		if (dds)														\
		  fprintf(stderr, "sll(): type = %d ; loc = %d ; as = %ld ; s = %ld ; ds = %ld ; dds = %ld\n", type, loc, actual_size, size, delta_size, dds); \
		*LOC_LOC(ptr) = tls_mallocations[0].loc;						\
	}
#else
#define SET_LOC_LOC(ptr, size)											\
	if (type && tls_mallocation_ptr) {									\
		ssize_t dds = actual_size - size;								\
		tls_mallocation_ptr->total_size += dds;							\
		*LOC_LOC(ptr) = tls_mallocations[0].loc;						\
	}
#endif

/*
 *  Set the memory allocation info. for an allocating operation.
 */
#define SET_ALLOC_INFO()  SET_MALLOCATION_INFO(ALLOC, 0)

/*
 *  Set the memory allocation info. for a freeing operation on the given pointer.
 */
#define SET_FREE_INFO(ptr)  SET_MALLOCATION_INFO(FREE, ptr)

/*
 *  Set the memory allocation info. for this operation.
 */
#define SET_MALLOCATION_INFO(alloc_or_free, ptr) \
	tls_mallocation_t *tls_mallocations = (tls_mallocation_t *) pthread_getspecific(tls_mallocations_key); \
	int type = -1;														\
	if (!tls_mallocations) {											\
		tls_mallocations = g_tls_mallocations;							\
		type = tls_mallocations[0].type;								\
	}																	\
	int loc = 0;														\
	tls_mallocation_t *tls_mallocation_ptr = NULL;						\
	ssize_t delta_size = 0;												\
	ssize_t total_size = 0;												\
	if (type == -1) {													\
		loc = ((ALLOC == (alloc_or_free)) ? tls_mallocations[0].loc : *LOC_LOC(ptr)); \
		tls_mallocation_ptr = &tls_mallocations[loc];					\
		delta_size = tls_mallocation_ptr->delta_size = tls_mallocations[0].delta_size; \
		total_size = tls_mallocation_ptr->total_size += tls_mallocations[0].delta_size; \
		type = tls_mallocation_ptr->type = tls_mallocations[0].type;	\
	}

#if 1
// XXX -- Send ds instead of delta_size.
#define MAYBE_DO_CB() \
	if (type && tls_mallocation_ptr) {									\
		ssize_t ds;														\
		if (FEATURE(ASM_LOG_MALLOCATIONS) && (labs(ds = (total_size - tls_mallocation_ptr->last_size)) > g_thresh_delta_size) && (labs(tls_mallocations[0].last_time.tv_sec - tls_mallocation_ptr->last_time.tv_sec) > g_thresh_delta_time)) { \
			dfprintf(stderr, "smi(): Call type %d @ loc %d delta_size = %ld total_size = %ld!\n", type, loc, delta_size, total_size); \
			if (g_cb) {													\
			    asm_thread_launcher_t *asmtl = (asm_thread_launcher_t *) pthread_getspecific(asmtl_key); \
				(g_cb)((asmtl ? asmtl->id : 0), type, loc, ds, total_size, &(tls_mallocations[0].last_time), g_cb_udata); \
			}															\
			tls_mallocation_ptr->last_size = total_size;				\
			tls_mallocation_ptr->last_time.tv_sec = tls_mallocations[0].last_time.tv_sec; \
			tls_mallocation_ptr->last_time.tv_nsec = tls_mallocations[0].last_time.tv_nsec; \
		}																\
	}
#else
#define MAYBE_DO_CB() \
	if (type && tls_mallocation_ptr) {									\
		if (FEATURE(ASM_LOG_MALLOCATIONS) && (labs(total_size - tls_mallocation_ptr->last_size) > g_thresh_delta_size) && (labs(tls_mallocations[0].last_time.tv_sec - tls_mallocation_ptr->last_time.tv_sec) > g_thresh_delta_time)) { \
			dfprintf(stderr, "smi(): Call type %d @ loc %d delta_size = %ld total_size = %ld!\n", type, loc, delta_size, total_size); \
			if (g_cb) {													\
			    asm_thread_launcher_t *asmtl = (asm_thread_launcher_t *) pthread_getspecific(asmtl_key); \
				(g_cb)((asmtl ? asmtl->id : 0), type, loc, delta_size, total_size, &(tls_mallocations[0].last_time), g_cb_udata); \
			}															\
			tls_mallocation_ptr->last_size = total_size;				\
			tls_mallocation_ptr->last_time.tv_sec = tls_mallocations[0].last_time.tv_sec; \
			tls_mallocation_ptr->last_time.tv_nsec = tls_mallocations[0].last_time.tv_nsec; \
		}																\
	}
#endif

/*
 *  Type representing the state of a memory allocation location in a program.
 */
typedef struct tls_mallocation_s {
	ssize_t total_size;                   // Cumulative net total size allocated by this thread.
	ssize_t delta_size;                   // Most recent change in size.
	ssize_t last_size;                    // Total size last reported change from this location.
	struct timespec last_time;            // Time of last reported change from this location.
	uint16_t type;                        // Type of the last memory allocation-related operation.
	uint16_t loc;                         // Location of the allocation in the program.
} __attribute__((__packed__)) tls_mallocation_t;

/*
 *  Memory allocation locations for the main process (i.e., not in any thread.)
 */
static tls_mallocation_t g_tls_mallocations[MAX_TLS_MALLOCATIONS];

/*
 *  Thread-specific storage key holding a pointer to the ASM thread launcher.
 */
static pthread_key_t asmtl_key;

/*
 *  Thread-specific storage key holding the memory allocation location information.
 */
static pthread_key_t tls_mallocations_key;

/*
 *  Callback function registered by the program.
 */
static void (*g_cb)(uint64_t thread_id, uint16_t type, uint16_t loc, ssize_t delta_size, ssize_t total_size, struct timespec *last_time, void *udata) = NULL;

/*
 *  User-supplied private data to be passed to the callback function.
 */
static void *g_cb_udata = NULL;

/*
 *  Have we been initialized?
 */
static bool inited = false;

/*
 *  ASMalloc memory statistics (written on the hook thread.)
 */
static asm_stats_t g_asm_stats;

/*
 *  Lock to serialize memory counting.
 */
static pthread_mutex_t init_lock = PTHREAD_MUTEX_INITIALIZER;

// Function pointer variables for the shadowed original functions.
static int (*original_pthread_create)(pthread_t *thread, const pthread_attr_t *attr, void *(*start_routine)(void *), void *arg);
static void *(*original_calloc)(size_t nmemb, size_t size);
static void *(*original_malloc)(size_t size);
static void (*original_free)(void *ptr);
static void *(*original_realloc)(void *ptr, size_t size);
static char *(*original_strdup)(const char *s);
static char *(*original_strndup)(const char *s, size_t n);
static int (*original_posix_memalign)(void **memptr, size_t alignment, size_t size);

static int (*original_brk)(void *addr);
static void *(*original_sbrk)(intptr_t increment);
static void *(*original___default_morecore)(ptrdiff_t __size);

#ifdef FOR_JEMALLOC
static void *(*original_mallocx)(size_t size, int flags);
static void *(*original_rallocx)(void *ptr, size_t size, int flags);
static void (*original_malloc_stats_print)(void (*write_cb)(void *, const char *), void *je_cbopaque, const char *opts);
#else
static void *(*original_mmap)(void *addr, size_t length, int prot, int flags, int fd, off_t offset);
static void *(*original_mmap64)(void *addr, size_t length, int prot, int flags, int fd, off64_t offset);
static int (*original_munmap)(void *addr, size_t length);
#endif

static void *(*original_shmat)(int shmid, const void *shmaddr, int shmflg);
static int (*original_shmctl)(int shmid, int cmd, struct shmid_ds *buf);
static int (*original_shmdt)(const void *shmaddr);
static int (*original_shmget)(key_t key, size_t size, int shmflg);


/*****************************************************************************************/

/*
 *  Basic Atomics.
 */

typedef volatile uint64_t cf_atomic64;

#define cf_atomic64_get(a) (a)
#define cf_atomic64_set(a, b) (*(a) = (b))

static inline int64_t
cf_atomic64_add(cf_atomic64 *a, int64_t b)
{
	int64_t i = b;

	__asm__ __volatile__ ("lock; xaddq %0, %1" : "+r" (b), "+m" (*a) : : "memory");

	return(b + i);
}
#define cf_atomic64_sub(a,b) (cf_atomic64_add((a), (0 - (b))))
#define cf_atomic64_incr(a) (cf_atomic64_add((a), 1))
#define cf_atomic64_decr(a) (cf_atomic64_add((a), -1))

/*****************************************************************************************/

// Counter for created pthreads.
static cf_atomic64 thread_id = 0;

// Number of currently alive pthreads.
static cf_atomic64 live_threads = 0;

// Counters for numbers of allocation function calls.
cf_atomic64 mem_count = 0;
cf_atomic64 mem_count_mallocs = 0;
cf_atomic64 mem_count_frees = 0;
cf_atomic64 mem_count_callocs = 0;
cf_atomic64 mem_count_reallocs = 0;
cf_atomic64 mem_count_strdups = 0;
cf_atomic64 mem_count_strndups = 0;
cf_atomic64 mem_count_vallocs = 0;

cf_atomic64 mem_count_brks = 0;
cf_atomic64 mem_count_sbrks = 0;
cf_atomic64 mem_count_morecores = 0;

#ifdef FOR_JEMALLOC
cf_atomic64 mem_count_mallocxs = 0;
cf_atomic64 mem_count_rallocxs = 0;

cf_atomic64 mem_count_mallocx_total = 0;
cf_atomic64 mem_count_rallocx_plus_total = 0;
cf_atomic64 mem_count_rallocx_minus_total = 0;
#endif

cf_atomic64 mem_count_net_mmaps = 0;
cf_atomic64 mem_count_mmaps = 0;
cf_atomic64 mem_count_mmap64s = 0;
cf_atomic64 mem_count_munmaps = 0;

// Counters for numbers bytes allocated / released by allocation function calls.
cf_atomic64 mem_count_malloc_total = 0;
cf_atomic64 mem_count_free_total = 0;
cf_atomic64 mem_count_calloc_total = 0;
cf_atomic64 mem_count_realloc_plus_total = 0;
cf_atomic64 mem_count_realloc_minus_total = 0;
cf_atomic64 mem_count_strdup_total = 0;
cf_atomic64 mem_count_strndup_total = 0;
cf_atomic64 mem_count_valloc_total = 0;

cf_atomic64 mem_count_sbrk_total = 0;
cf_atomic64 mem_count_morecore_total = 0;

cf_atomic64 mem_count_net_mmap_total = 0;
cf_atomic64 mem_count_mmap_total = 0;
cf_atomic64 mem_count_mmap64_total = 0;
cf_atomic64 mem_count_munmap_total = 0;

cf_atomic64 mem_count_shmats = 0;
cf_atomic64 mem_count_shmctls = 0;
cf_atomic64 mem_count_shmdts = 0;
cf_atomic64 mem_count_shmgets = 0;
cf_atomic64 mem_count_net_shm = 0;

/*
 *  Initialize the memory accounting statistics.
 */
static void init_counters(void) 
{
	memset(&g_asm_stats, sizeof(g_asm_stats), 0);

	cf_atomic64_set(&mem_count, 0);
	cf_atomic64_set(&mem_count_mallocs, 0);
	cf_atomic64_set(&mem_count_frees, 0);
	cf_atomic64_set(&mem_count_callocs, 0);
	cf_atomic64_set(&mem_count_reallocs, 0);
	cf_atomic64_set(&mem_count_strdups, 0);
	cf_atomic64_set(&mem_count_strndups, 0);
	cf_atomic64_set(&mem_count_vallocs, 0);

	cf_atomic64_set(&mem_count_brks, 0);
	cf_atomic64_set(&mem_count_sbrks, 0);
	cf_atomic64_set(&mem_count_morecores, 0);

#ifdef FOR_JEMALLOC
	cf_atomic64_set(&mem_count_mallocxs, 0);
	cf_atomic64_set(&mem_count_rallocxs, 0);

	cf_atomic64_set(&mem_count_mallocx_total, 0);
	cf_atomic64_set(&mem_count_rallocx_plus_total, 0);
	cf_atomic64_set(&mem_count_rallocx_minus_total, 0);
#endif

	cf_atomic64_set(&mem_count_net_mmaps, 0);
	cf_atomic64_set(&mem_count_mmaps, 0);
	cf_atomic64_set(&mem_count_mmap64s, 0);
	cf_atomic64_set(&mem_count_munmaps, 0);

	cf_atomic64_set(&mem_count_malloc_total, 0);
	cf_atomic64_set(&mem_count_free_total, 0);
	cf_atomic64_set(&mem_count_calloc_total, 0);
	cf_atomic64_set(&mem_count_realloc_plus_total, 0);
	cf_atomic64_set(&mem_count_realloc_minus_total, 0);
	cf_atomic64_set(&mem_count_strdup_total, 0);
	cf_atomic64_set(&mem_count_strndup_total, 0);
	cf_atomic64_set(&mem_count_valloc_total, 0);

	cf_atomic64_set(&mem_count_sbrk_total, 0);
	cf_atomic64_set(&mem_count_morecore_total, 0);

	cf_atomic64_set(&mem_count_net_mmap_total, 0);
	cf_atomic64_set(&mem_count_mmap_total, 0);
	cf_atomic64_set(&mem_count_mmap64_total, 0);
	cf_atomic64_set(&mem_count_munmap_total, 0);

	cf_atomic64_set(&mem_count_shmats, 0);
	cf_atomic64_set(&mem_count_shmctls, 0);
	cf_atomic64_set(&mem_count_shmdts, 0);
	cf_atomic64_set(&mem_count_shmgets, 0);
	cf_atomic64_set(&mem_count_net_shm, 0);

	cf_atomic64_set(&thread_id, 0);
	cf_atomic64_set(&live_threads, 0);
}

/*****************************************************************************************/

/*
 *  Print the current GLibC heap statistics.
 */
static void asm_log_datestamp(void)
{
	char datestamp[100];
	struct tm nowtm;
	time_t now = time(NULL);
	gmtime_r(&now, &nowtm);
	strftime(datestamp, sizeof(datestamp), "\n%b %d %Y %T %Z:\n\n", &nowtm);

	fprintf(stderr, datestamp);
}

/*
 *  Print the number of threads.
 */
static void asm_thread_stats(void)
{
	fprintf(stderr, ">>>There are %lu live (out of %lu total) threads.<<<\n\n", live_threads, thread_id);
	fflush(stderr);
}

/*
 *  Print the current GLibC heap info. in a self-describing format.
 */
static void asm_log_malloc_info(void)
{
	malloc_info(0, stderr);
	fprintf(stderr, "\n");
}

/*
 *  Print the current GLibC heap statistics.
 *
 *  [Note:  This is only 32-bits due to the 
 */
static void asm_log_malloc_stats(void)
{
	malloc_stats();
	fprintf(stderr, "\n");
}

/*
 *  Print GLibC heap usage statistics.
 *
 *  [Note:  This only describes the main arena.]
 */
static void asm_log_mallinfo(void)
{
	struct mallinfo mi = mallinfo();

	fprintf(stderr, "struct mallinfo = {\n");
	fprintf(stderr, "\tarena = %d;\t\t/* non-mmapped space allocated from system */\n", mi.arena);
	fprintf(stderr, "\tordblks = %d;\t\t/* number of free chunks */\n", mi.ordblks);
	fprintf(stderr, "\tsmblks = %d;\t\t/* number of fastbin blocks */ *GLIBC UNUSED*\n", mi.smblks);
	fprintf(stderr, "\thblks = %d;\t\t/* number of mmapped regions */\n", mi.hblks);
	fprintf(stderr, "\thblkhd = %d;\t\t/* space in mmapped regions */\n", mi.hblkhd);
	fprintf(stderr, "\tusmblks = %d;\t\t/* maximum total allocated space */ *GLIBC UNUSED*\n", mi.usmblks);
	fprintf(stderr, "\tfsmblks = %d;\t\t/* space available in freed fastbin blocks */ *GLIBC UNUSED*\n", mi.fsmblks);
	fprintf(stderr, "\tuordblks = %d;\t\t/* total allocated space */\n", mi.uordblks);
	fprintf(stderr, "\tfordblks = %d;\t\t/* total free space */\n", mi.fordblks);
	fprintf(stderr, "\tkeepcost = %d;\t\t/* top-most, releasable (via malloc_trim) space */\n", mi.keepcost);
	fprintf(stderr, "}\n");

	size_t total_used = mi.arena + mi.hblkhd - mi.fordblks;

	fprintf(stderr, "total_used: %zu ; diff: %ld\n", total_used, total_used - mem_count);
}

/*
 *  Return human-readable value (in terms of floting point powers of 2 ^ 10) for a given memory size.
 */
static void get_human_readable_memory_size(ssize_t sz, double *quantity, char **scale)
{
	size_t asz = labs(sz);

	if (asz >= (1 << 30)) {
		*scale = "GB";
		*quantity = ((double) sz) / exp2(30.0);
	} else if (asz >= (1 << 20)) {
		*scale = "MB";
		*quantity = ((double) sz) / exp2(20.0);
	} else if (asz >= (1 << 10)) {
		*scale = "KB";
		*quantity = ((double) sz) / exp2(10.0);
	} else {
		*scale = "B";
		*quantity = (double) sz;
	}
}

/*
 *  Print the current memory allocation statistics.
 */
static void asm_mem_count_stats()
{
	fprintf(stderr, "Mem Count Stats:\n");
	fprintf(stderr, "=============================================\n");

	size_t mc = cf_atomic64_get(mem_count);
	double quantity = 0.0;
	char *scale = "B";
	get_human_readable_memory_size(mc, &quantity, &scale);

	size_t mcm = cf_atomic64_get(mem_count_mallocs);
	size_t mcf = cf_atomic64_get(mem_count_frees);
	size_t mcc = cf_atomic64_get(mem_count_callocs);
	size_t mcr = cf_atomic64_get(mem_count_reallocs);
	size_t mcs = cf_atomic64_get(mem_count_strdups);
	size_t mcsn = cf_atomic64_get(mem_count_strndups);
	size_t mcv = cf_atomic64_get(mem_count_vallocs);

#ifdef FOR_JEMALLOC
	size_t mcmx = cf_atomic64_get(mem_count_mallocxs);
	size_t mcrx = cf_atomic64_get(mem_count_rallocxs);
#endif

	fprintf(stderr, "mem_count: %ld (%.3f %s)\n", mc, quantity, scale);
	fprintf(stderr, "=============================================\n");
	fprintf(stderr, "net mallocs: %ld\n", (mcm + mcc + mcv + mcs + mcsn - mcf));
	fprintf(stderr, "=============================================\n");
	fprintf(stderr, "mem_count_mallocs: %ld (%ld)\n", mcm, cf_atomic64_get(mem_count_malloc_total));
	fprintf(stderr, "mem_count_frees: %ld (%ld)\n", mcf, cf_atomic64_get(mem_count_free_total));
	fprintf(stderr, "mem_count_callocs: %ld (%ld)\n", mcc, cf_atomic64_get(mem_count_calloc_total));
	fprintf(stderr, "mem_count_reallocs: %ld (%ld / %ld)\n", mcr, cf_atomic64_get(mem_count_realloc_plus_total), cf_atomic64_get(mem_count_realloc_minus_total));
	fprintf(stderr, "mem_count_strdups: %ld (%ld)\n", mcs, cf_atomic64_get(mem_count_strdup_total));
	fprintf(stderr, "mem_count_strndups: %ld (%ld)\n", mcsn, cf_atomic64_get(mem_count_strndup_total));
	fprintf(stderr, "mem_count_vallocs: %ld (%ld)\n", mcv, cf_atomic64_get(mem_count_valloc_total));
	fprintf(stderr, "=============================================\n");
#ifdef FOR_JEMALLOC
	fprintf(stderr, "mem_count_mallocxs: %ld (%ld)\n", mcmx, cf_atomic64_get(mem_count_mallocx_total));
	fprintf(stderr, "mem_count_rallocxs: %ld (%ld / %ld)\n", mcrx, cf_atomic64_get(mem_count_rallocx_plus_total), cf_atomic64_get(mem_count_rallocx_minus_total));
	fprintf(stderr, "=============================================\n");
#endif

	quantity = 0.0;
	scale = "B";
	size_t sbt = cf_atomic64_get(mem_count_sbrk_total);
	get_human_readable_memory_size(sbt, &quantity, &scale);

	fprintf(stderr, "mem_count_brks: %ld\n", cf_atomic64_get(mem_count_brks));
	fprintf(stderr, "mem_count_sbrks: %ld\n", cf_atomic64_get(mem_count_sbrks));
	fprintf(stderr, "mem_count_sbrk_total: %ld (%.3f %s)\n", sbt, quantity, scale);

	quantity = 0.0;
	scale = "B";
	size_t mct = cf_atomic64_get(mem_count_morecore_total);
	get_human_readable_memory_size(mct, &quantity, &scale);

	fprintf(stderr, "mem_count_morecores: %ld\n", cf_atomic64_get(mem_count_morecores));
	fprintf(stderr, "mem_count_morecore_total: %ld (%.3f %s)\n", mct, quantity, scale);
	fprintf(stderr, "=============================================\n");

	quantity = 0.0;
	scale = "B";
	size_t nmt = cf_atomic64_get(mem_count_net_mmap_total);
	get_human_readable_memory_size(nmt, &quantity, &scale);

	fprintf(stderr, "net mmaps: %ld : %ld (%.3f %s)\n", cf_atomic64_get(mem_count_net_mmaps), nmt, quantity, scale);
	fprintf(stderr, "=============================================\n");
	fprintf(stderr, "mem_count_mmaps: %ld (%ld)\n", cf_atomic64_get(mem_count_mmaps), cf_atomic64_get(mem_count_mmap_total));
	fprintf(stderr, "mem_count_mmap64s: %ld (%ld)\n", cf_atomic64_get(mem_count_mmap64s), cf_atomic64_get(mem_count_mmap64_total));
	fprintf(stderr, "mem_count_munmaps: %ld (%ld)\n", cf_atomic64_get(mem_count_munmaps), cf_atomic64_get(mem_count_munmap_total));
	fprintf(stderr, "=============================================\n");

	quantity = 0.0;
	scale = "B";
	size_t nshm = cf_atomic64_get(mem_count_net_shm);
	get_human_readable_memory_size(nshm, &quantity, &scale);

	fprintf(stderr, "net shms: %ld (%.3f %s)\n", nshm, quantity, scale);
	fprintf(stderr, "=============================================\n");
	fprintf(stderr, "mem_count_shmats: %ld\n", cf_atomic64_get(mem_count_shmats));
	fprintf(stderr, "mem_count_shmctls: %ld\n", cf_atomic64_get(mem_count_shmctls));
	fprintf(stderr, "mem_count_shmdts: %ld\n", cf_atomic64_get(mem_count_shmdts));
	fprintf(stderr, "mem_count_shmgets: %ld\n", cf_atomic64_get(mem_count_shmgets));
	fprintf(stderr, "=============================================\n\n");

	// Snap-shot the current usage of various types of memory.
	g_asm_stats.mem_count = mc;
	g_asm_stats.net_mmaps = nmt;
	g_asm_stats.net_shm = nshm;
}

/*
 *  ASM version of the hook function.
 */
int asm_hook(void *arg, asm_stats_t **asm_stats, vm_stats_t **vm_stats)
{
	dfprintf(stderr, ">>>In asm_hook(%p)<<<\n", arg);

	if (asm_stats) {
		*asm_stats = &g_asm_stats;
	}

	if (FEATURE(ASM_LOG_DATESTAMP)) {
		asm_log_datestamp();
	}

	if (FEATURE(ASM_LOG_THREAD_STATS)) {
		asm_thread_stats();
	}

	if (FEATURE(ASM_LOG_MEM_COUNT_STATS)) {
		asm_mem_count_stats();
	}

	if (FEATURE(ASM_LOG_MALLOC_INFO)) {
		asm_log_malloc_info();
	}

	if (FEATURE(ASM_LOG_MALLOC_STATS)) {
		asm_log_malloc_stats();
	}

	if (FEATURE(ASM_LOG_MALLINFO)) {
		// [Note:  This only describes the main arena.]
		asm_log_mallinfo();
	}

	if (FEATURE(ASM_LOG_VM_STATS)) {
		vm_stats_t *stats = log_vm_stats(getpid());

		if (vm_stats) {
			*vm_stats = stats;
		}
	}

	return 0;
}

/*
 *  ASM version of the command function.
 */
int asm_cmd(asm_cmd_t cmd, va_list args)
{
	dfprintf(stderr, ">>>In asm_cmd(%d)<<<\n", cmd);

	// Handle variable arguments.
	switch (cmd) {
	  case ASM_CMD_SET_FEATURES:
	  {
		  g_features = va_arg(args, uint64_t);
		  dfprintf(stderr, ">>>ASM_CMD_SET_FEATURES: \"0x%lx\"<<<\n", g_features);
		  break;
	  }

	  case ASM_CMD_SET_CALLBACK:
		  g_cb = va_arg(args, void *);
		  g_cb_udata = va_arg(args, void *);
		  dfprintf(stderr, ">>>ASM_CMD_SET_CALLBACK: g_cb = %p ; g_cb_udata = %p<<<\n", g_cb, g_cb_udata);
		  break;

	  case ASM_CMD_SET_THRESHOLDS:
		  g_thresh_block_size = va_arg(args, size_t);
		  g_thresh_delta_size = va_arg(args, size_t);
		  g_thresh_delta_time = va_arg(args, time_t);
		  dfprintf(stderr, ">>>ASM_CMD_SET_THRESHOLDS: g_thresh_block_size = %lu ; g_thresh_delta_size = %lu ; g_thresh_delta_time = %lu<<<\n",
				   g_thresh_block_size, g_thresh_delta_size, g_thresh_delta_time);
		  break;

	  case ASM_CMD_PRINT_STATS:
#ifdef FOR_JEMALLOC
		  if (original_malloc_stats_print) {
			  original_malloc_stats_print(NULL, NULL, NULL);
		  } else {
			  fprintf(stderr, ">>>original_malloc_stats_print() is NULL!<<<\n");
		  }
#endif
		  break;

	  default:
		  break;
	}

	return 0;
}

/*
 *  Initialize the memory wrappers.
 */
static bool init(int i)
{
	dfprintf(stderr, ">>>In asm init(1)<<<\n");

	pthread_mutex_lock(&init_lock);

	dfprintf(stderr, ">>>In asm init(2)<<<\n");

	if (!inited) {
		init_counters();

		if (!(original_calloc = dlsym(RTLD_NEXT, "calloc"))) {
			fprintf(stderr, "Could not find original calloc()!\n");
		}

		if (!(original_malloc = dlsym(RTLD_NEXT, "malloc"))) {
			fprintf(stderr, "Could not find original malloc()!\n");
		}

		if (!(original_free = dlsym(RTLD_NEXT, "free"))) {
			fprintf(stderr, "Could not find original free()!\n");
		}

		if (!(original_realloc = dlsym(RTLD_NEXT, "realloc"))) {
			fprintf(stderr, "Could not find original realloc()!\n");
		}

		if (!(original_strdup = dlsym(RTLD_NEXT, "strdup"))) {
			fprintf(stderr, "Could not find original strdup()!\n");
		}

		if (!(original_strndup = dlsym(RTLD_NEXT, "strndup"))) {
			fprintf(stderr, "Could not find original strndup()!\n");
		}

		if (!(original_posix_memalign = dlsym(RTLD_NEXT, "posix_memalign"))) {
			fprintf(stderr, "Could not find original posix_memalign()!\n");
		}

		/********************************/

		if (!(original_brk = dlsym(RTLD_NEXT, "brk"))) {
			fprintf(stderr, "Could not find original brk()!\n");
		}

		if (!(original_sbrk = dlsym(RTLD_NEXT, "__sbrk"))) {
			fprintf(stderr, "Could not find original sbrk()!\n");
		}

		if (!(original___default_morecore = dlsym(RTLD_NEXT, "__default_morecore"))) {
			fprintf(stderr, "Could not find original __default_morecore()!\n");
		}
		__morecore = __default_morecore;

		/********************************/

#ifdef FOR_JEMALLOC
		if (!(original_mallocx = dlsym(RTLD_NEXT, "mallocx"))) {
			dfprintf(stderr, "Could not find \"mallocx\"!\n");
		}

		if (!(original_rallocx = dlsym(RTLD_NEXT, "rallocx"))) {
			dfprintf(stderr, "Could not find \"rallocx\"!\n");
		}

		if (!(original_malloc_stats_print = dlsym(RTLD_NEXT, "malloc_stats_print"))) {
			dfprintf(stderr, "Could not find \"malloc_stats_print\"!\n");
		}
#else

		if (!(original_mmap = dlsym(RTLD_NEXT, "mmap"))) {
			fprintf(stderr, "Could not find original mmap()!\n");
		}

		if (!(original_mmap64 = dlsym(RTLD_NEXT, "mmap64"))) {
			fprintf(stderr, "Could not find original mmap64()!\n");
		}

		if (!(original_munmap = dlsym(RTLD_NEXT, "munmap"))) {
			fprintf(stderr, "Could not find original munmap()!\n");
		}
#endif

		/********************************/

		if (!(original_shmat = dlsym(RTLD_NEXT, "shmat"))) {
			fprintf(stderr, "Could not find original shmat()!\n");
		}

		if (!(original_shmctl = dlsym(RTLD_NEXT, "shmctl"))) {
			fprintf(stderr, "Could not find original shmctl()!\n");
		}

		if (!(original_shmdt = dlsym(RTLD_NEXT, "shmdt"))) {
			fprintf(stderr, "Could not find original shmdt()!\n");
		}

		if (!(original_shmget = dlsym(RTLD_NEXT, "shmget"))) {
			fprintf(stderr, "Could not find original shmget()!\n");
		}

		inited = true;

		pthread_mutex_unlock(&init_lock);
	}

	return inited;
}

/*****************************************************************************************/

/*
 *  Thread-specific key destructor function for ASM thread launcher.
 */
static void asmtl_key_destructor(void *key)
{
	asm_thread_launcher_t *asmtl = (asm_thread_launcher_t *) key;

	fprintf(stderr, "Calling asmtl key destructor on thread #%lu: \"%s\" (%p) ; tid %lu!\n", asmtl->id, asmtl->sname, (void *) pthread_self(), syscall(SYS_gettid));

	cf_atomic64_decr(&live_threads);
}

/*
 *  Initialize the shared library.
 */
static void __attribute__ ((constructor)) begin(void)
{
#ifdef DEBUG
	BREAK();
	LOG('*');
	BREAK();
#endif

	dfprintf(stderr, ">>>In begin()<<<\n");

	// Zero-out the global statically-allocated array of memory allocation locations.
	memset(g_tls_mallocations, 0, MAX_TLS_MALLOCATIONS * sizeof(tls_mallocation_t));

	int rv;
	if ((rv = pthread_key_create(&asmtl_key, asmtl_key_destructor))) {
		fprintf(stderr, "pthread_key_create(asmtl_key) failed with rv = %d!\n", rv);
	}
	if ((rv = pthread_key_create(&tls_mallocations_key, NULL))) {
		fprintf(stderr, "pthread_key_create(tls_mallocations_key) failed with rv = %d!\n", rv);
	}

	INIT(1);
}

/*
 *  De-initialize the shared library.
 */
static void __attribute__ ((destructor)) end(void)
{
	dfprintf(stderr, ">>>In end()<<<\n");
}

/*****************************************************************************************/

/*
 *  Wrapper for thread start routines that sets up the thread-specific data
 *  needed for memory accounting.
 */
static void *asm_start_routine(void *arg)
{
	asm_thread_launcher_t *asmtl = (asm_thread_launcher_t *) arg;
	tls_mallocation_t tls_mallocations[MAX_TLS_MALLOCATIONS];
	tls_mallocation_t *tls_mallocations_ptr = tls_mallocations;

	// Zero-out the array of memory allocation locations allocated on the process' stack.
	memset(tls_mallocations_ptr, 0, MAX_TLS_MALLOCATIONS * sizeof(tls_mallocation_t));

	int rv;
	if ((rv = pthread_setspecific(asmtl_key, (void *) asmtl))) {
		fprintf(stderr, "Thread #%ld failed to set asmtl_key with rv = %d!\n", asmtl->id, rv);
	}
	if ((rv = pthread_setspecific(tls_mallocations_key, (void *) tls_mallocations_ptr))) {
		fprintf(stderr, "Thread #%ld failed to set asmtl_key with rv = %d!\n", asmtl->id, rv);
	}

	fprintf(stderr, "I am thread #%lu: \"%s\" (%p) ; tid %lu!\n", asmtl->id, asmtl->sname, (void *) pthread_self(), syscall(SYS_gettid));

	return asmtl->start_routine(asmtl->arg);
}

/*
 *  ASM version of pthread_create().
 */
int pthread_create(pthread_t *thread, const pthread_attr_t *attr, void *(*start_routine)(void *), void *arg)
{
	asm_thread_launcher_t *asmtl = (asm_thread_launcher_t *) calloc(1, sizeof(asm_thread_launcher_t));
	asmtl->id = cf_atomic64_incr(&thread_id);
	asmtl->start_routine = start_routine;
	asmtl->arg = arg;
	asmtl->sname = NULL;

	Dl_info dl_info;
	if (dladdr(asmtl->start_routine, &dl_info)) {
		asmtl->sname = dl_info.dli_sname;
	} else {
		fprintf(stderr, "Failed to get Dl_info for start routine %p!\n", asmtl->start_routine);
	}

	fprintf(stderr, "Created thread #%lu: start_routine = %p ; arg = %p\n", asmtl->id, start_routine, arg);
	cf_atomic64_incr(&live_threads);

	if (!original_pthread_create) {
		if (!(original_pthread_create = dlsym(RTLD_NEXT, "pthread_create"))) {
			fprintf(stderr, "Could not find original pthread_create()!\n");
			return EAGAIN;
		}
	}

	return original_pthread_create(thread, attr, asm_start_routine, asmtl);
}

/*
 *  Store the type and location of a mallocation in thread-specific storage.
 */
void asm_mallocation_set(uint16_t type, uint16_t loc, ssize_t delta_size)
{
	tls_mallocation_t *tls_mallocations = (tls_mallocation_t *) pthread_getspecific(tls_mallocations_key);

	// Use the global array for any calls from the main process.
	if (!tls_mallocations) {
		tls_mallocations = g_tls_mallocations;
	}

	// The 0th mallocation is used to pass information from the program to this module.
	// [Note:  Total size of the 0th mallocation is always 0.]
	tls_mallocations[0].delta_size = delta_size;
	tls_mallocations[0].type = type;
	tls_mallocations[0].loc = loc;

	// Set the time of the event.
	clock_gettime(CLOCK_MONOTONIC, &(tls_mallocations[0].last_time));

	// Log large block (de)allocations.
	if (FEATURE(ASM_LOG_BLOCKS) && (delta_size > g_thresh_block_size)) {
		dfprintf(stderr, "ams(): Call type %d @ loc %d delta_size = %ld!\n", type, loc, delta_size);
		if (g_cb) {
			asm_thread_launcher_t *asmtl = (asm_thread_launcher_t *) pthread_getspecific(asmtl_key);
			// [Note:  Thread #0 is the main process / initial thread.]
			(g_cb)((asmtl ? asmtl->id : 0), type, loc, delta_size, 0, &(tls_mallocations[0].last_time), g_cb_udata);
		}
	}
}

/*
 *  Return the type and location of a mallocation in thread-specific storage.
 */
void asm_mallocation_get(uint16_t *type, uint16_t loc, ssize_t *total_size, ssize_t *delta_size, struct timespec *last_time)
{
	tls_mallocation_t *tls_mallocations = (tls_mallocation_t *) pthread_getspecific(tls_mallocations_key);

	// Use the global array for any calls from the main process.
	if (!tls_mallocations) {
		tls_mallocations = g_tls_mallocations;
	}

	if (type) {
		*type = tls_mallocations[loc].type;
	}
	// [Note:  The loc is only passed in.]
	if (total_size) {
		*total_size = tls_mallocations[loc].total_size;
	}
	if (delta_size) {
		*delta_size = tls_mallocations[loc].delta_size;
	}

	if (last_time) {
		last_time->tv_sec = tls_mallocations[loc].last_time.tv_sec;
		last_time->tv_nsec = tls_mallocations[loc].last_time.tv_nsec;
	}
}

/******************************** MALLOC/FREE and Friends ********************************/

/*
 *  ASM version of calloc(3).
 */
void *calloc(size_t nmemb, size_t size)
{
	INIT(2);

	// Handle allocation request in "dlerror()" when multithreaded.
	if (!inited) {
		size_t requested = nmemb * size;
		if (requested > haksize) {
			// [Note:  Only the lower 8 bits will be returned as the exit status.]
			exit(requested);
		}
		void *result = (void *) hakbuf_ptr;
		hakbuf_ptr += requested;
		haksize -= requested;

		cf_atomic64_incr(&mem_count_callocs);
		cf_atomic64_add(&mem_count, requested);
		cf_atomic64_add(&mem_count_calloc_total, requested);

		return result;
	}

	cf_atomic64_incr(&mem_count_callocs);
	dfprintf(stderr, ">>>In asm calloc()<<<\n");

	SET_ALLOC_INFO();

	// Reserve space for the allocation location.
	// XXX -- Overallocates by (4 * (nmemb - 1)) bytes.
	size += sizeof(int);

	void *retval = original_calloc(nmemb, size);

	size_t actual_size = malloc_usable_size(retval);
	cf_atomic64_add(&mem_count, actual_size);
	cf_atomic64_add(&mem_count_calloc_total, actual_size);

	SET_LOC_LOC(retval, nmemb * size);

	MAYBE_DO_CB();

	return retval;
}

/*
 *  ASM version of malloc(3).
 */
void *malloc(size_t size)
{
	INIT(3);

	SET_ALLOC_INFO();

	// Reserve space for the allocation location.
	size += sizeof(int);

	void *retval = original_malloc(size);

	size_t actual_size = malloc_usable_size(retval);
	cf_atomic64_add(&mem_count, actual_size);
	cf_atomic64_add(&mem_count_malloc_total, actual_size);

	cf_atomic64_incr(&mem_count_mallocs);
	dfprintf(stderr, ">>>In asm malloc()<<<\n");

	SET_LOC_LOC(retval, size);

	MAYBE_DO_CB();

	return retval;
}

/*
 *  ASM version of free(3).
 */
void free(void *ptr)
{
	INIT(4);

	// Only count non-"free(0)"'s.
	if (ptr) {
		cf_atomic64_incr(&mem_count_frees);
		dfprintf(stderr, ">>>In asm free(%p)<<<\n", ptr);

		size_t actual_size = malloc_usable_size(ptr);

		SET_FREE_INFO(ptr);

		cf_atomic64_sub(&mem_count, actual_size);
		cf_atomic64_sub(&mem_count_free_total, actual_size);

		MAYBE_DO_CB();
	}

	original_free(ptr);
}

/*
 *  ASM version of realloc(3).
 */
void *realloc(void *ptr, size_t size)
{
	INIT(5);

	cf_atomic64_incr(&mem_count_reallocs);
	dfprintf(stderr, ">>>In asm realloc()<<<\n");

	int64_t orig_size = (ptr ? malloc_usable_size(ptr) : 0);
	int64_t	delta = 0;

	// Reserve space for the allocation location.
	if (size) {
		size += sizeof(int);
	}

	void *retval = original_realloc(ptr, size);

	if (!size) {
		delta = - orig_size;
	} else {
		// [Note:  If realloc() fails, NULL is returned and the original block is left unchanged.]
		if (retval) {
			delta = malloc_usable_size(retval) - orig_size;
		}
	}
	SET_MALLOCATION_INFO((!size ? FREE : ALLOC), ptr);

	cf_atomic64_add(&mem_count, delta);
	if (delta > 0) {
		cf_atomic64_add(&mem_count_realloc_plus_total, delta);
	} else {
		cf_atomic64_add(&mem_count_realloc_minus_total, delta);
	}

	if (!ptr) {
		cf_atomic64_incr(&mem_count_mallocs);
	} else if (!size) {
		cf_atomic64_incr(&mem_count_frees);
	} else {
		cf_atomic64_incr(&mem_count_frees);
		cf_atomic64_incr(&mem_count_mallocs);
	}

	// Only set the allocation location for non-free()-type realloc()'s.
	if (size) {
		size_t actual_size = malloc_usable_size(retval);
		SET_LOC_LOC(retval, size);
	}

	MAYBE_DO_CB();

	return retval;
}

/*
 *  ASM version of strdup(3).
 */
char *strdup(const char *s)
{
	INIT(6);

	cf_atomic64_incr(&mem_count_strdups);
	dfprintf(stderr, ">>>In asm strdup()<<<\n");

	SET_ALLOC_INFO();

	char *retval = original_strdup(s);

	cf_atomic64_add(&mem_count_strdup_total, malloc_usable_size(retval));

	// XXX -- How do we set the loc?

	MAYBE_DO_CB();

	return retval;
}

/*
 *  ASM version of strndup(3).
 */
char *strndup(const char *s, size_t n)
{
	INIT(7);

	cf_atomic64_incr(&mem_count_strndups);
	dfprintf(stderr, ">>>In asm strndup()<<<\n");

	SET_ALLOC_INFO();

	char *retval = original_strndup(s, n);

	cf_atomic64_add(&mem_count_strndup_total, malloc_usable_size(retval));

	// XXX -- How do we set the loc?

	MAYBE_DO_CB();

	return retval;
}

/*
 *  ASM version of posix_memalign(3).
 */
int posix_memalign(void **memptr, size_t alignment, size_t size)
{
	INIT(8);

	cf_atomic64_incr(&mem_count_vallocs);
	dfprintf(stderr, ">>>In asm posix_memalign()<<<\n");

	// Reserve space for the allocation location.
	size += sizeof(int);

	SET_ALLOC_INFO();

	int retval = original_posix_memalign(memptr, alignment, size);

	size_t actual_size = (memptr ? malloc_usable_size(*memptr) : 0);
	if (memptr) {
		cf_atomic64_add(&mem_count, actual_size);
		cf_atomic64_add(&mem_count_valloc_total, actual_size);
	}

	SET_LOC_LOC(*memptr, size);

	MAYBE_DO_CB();

	return retval;
}

/******************************** BRK/SBRK/MORECORE ********************************/

/*
 *  ASM version of brk(2).
 */
int brk(void *addr)
{
	INIT(9);

	cf_atomic64_incr(&mem_count_brks);
	dfprintf(stderr, ">>>In asm brk()<<<\n");

	int retval = original_brk(addr);

	return retval;
}

/*
 *  ASM version of sbrk(2).
 */
void *__sbrk(intptr_t increment)
{
	INIT(10);

	cf_atomic64_incr(&mem_count_sbrks);
	dfprintf(stderr, ">>>In asm sbrk()<<<\n");

	void *retval = original_sbrk(increment);

	cf_atomic64_add(&mem_count_sbrk_total, increment);

	return retval;
}

/*
 *  ASM version of __default_morecore().
 */
void *__default_morecore(ptrdiff_t __size)
{
	INIT(11);

	cf_atomic64_incr(&mem_count_morecores);
	dfprintf(stderr, ">>>In asm __default_morecore()<<<\n");

	void *retval = original___default_morecore(__size);

	cf_atomic64_add(&mem_count_morecore_total, __size);

	return retval;
}

#ifdef FOR_JEMALLOC

/******************************** JEMALLOC NON-STANDARD API ******************************/

/*
 *  ASM version of mallocx(3).
 *  (Treat essentially like malloc(3).)
 */
void *mallocx(size_t size, int flags)
{
	INIT(12);

	SET_ALLOC_INFO();

	// Reserve space for the allocation location.
	size += sizeof(int);

	void *retval = original_mallocx(size, flags);

	size_t actual_size = malloc_usable_size(retval);
	cf_atomic64_add(&mem_count, actual_size);
	cf_atomic64_add(&mem_count_malloc_total, actual_size);
	cf_atomic64_add(&mem_count_mallocx_total, actual_size);

	cf_atomic64_incr(&mem_count_mallocs);
	cf_atomic64_incr(&mem_count_mallocxs);
	dfprintf(stderr, ">>>In asm mallocx()<<<\n");

	SET_LOC_LOC(retval, size);

	MAYBE_DO_CB();

	return retval;
}

/*
 *  ASM version of rallocx(3).
 *  (Treat essentially like realloc(3).)
 */
void *rallocx(void *ptr, size_t size, int flags)
{
	INIT(13);

	cf_atomic64_incr(&mem_count_reallocs);
	cf_atomic64_incr(&mem_count_rallocxs);
	dfprintf(stderr, ">>>In asm reallocx()<<<\n");

	int64_t orig_size = (ptr ? malloc_usable_size(ptr) : 0);
	int64_t	delta = 0;

	// Reserve space for the allocation location.
	if (size) {
		size += sizeof(int);
	}

	void *retval = original_rallocx(ptr, size, flags);

	if (!size) {
		delta = - orig_size;
	} else {
		// [Note:  If rallocx() fails, NULL is returned and the original block is left unchanged.]
		if (retval) {
			delta = malloc_usable_size(retval) - orig_size;
		}
	}
	SET_MALLOCATION_INFO((!size ? FREE : ALLOC), ptr);

	cf_atomic64_add(&mem_count, delta);
	if (delta > 0) {
		cf_atomic64_add(&mem_count_realloc_plus_total, delta);
		cf_atomic64_add(&mem_count_rallocx_plus_total, delta);
	} else {
		cf_atomic64_add(&mem_count_realloc_minus_total, delta);
		cf_atomic64_add(&mem_count_rallocx_minus_total, delta);
	}

	if (!ptr) {
		cf_atomic64_incr(&mem_count_mallocs);
	} else if (!size) {
		cf_atomic64_incr(&mem_count_frees);
	} else {
		cf_atomic64_incr(&mem_count_frees);
		cf_atomic64_incr(&mem_count_mallocs);
	}

	// Only set the allocation location for non-free()-type rallocx()'s.
	if (size) {
		size_t actual_size = malloc_usable_size(retval);
		SET_LOC_LOC(retval, size);
	}

	MAYBE_DO_CB();

	return retval;
}

#else

/****************************************** MMAP *****************************************/

/*
 *  ASM version of mmap(2).
 */
void *mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset)
{
	INIT(12);

	cf_atomic64_incr(&mem_count_mmaps);
	cf_atomic64_incr(&mem_count_net_mmaps);
	dfprintf(stderr, ">>>In asm mmap()<<<\n");

	void *retval = original_mmap(addr, length, prot, flags, fd, offset);

	cf_atomic64_add(&mem_count_mmap_total, length);
	cf_atomic64_add(&mem_count_net_mmap_total, length);

	return retval;
}

/*
 *  ASM version of mmap64(2).
 */
void *mmap64(void *addr, size_t length, int prot, int flags, int fd, off64_t offset)
{
	INIT(13);

	cf_atomic64_incr(&mem_count_mmap64s);
	cf_atomic64_incr(&mem_count_net_mmaps);
	dfprintf(stderr, ">>>In asm mmap64()<<<\n");

	void *retval = original_mmap64(addr, length, prot, flags, fd, offset);

	cf_atomic64_add(&mem_count_mmap64_total, length);
	cf_atomic64_add(&mem_count_net_mmap_total, length);

	return retval;
}

/*
 *  ASM version of munmap(2).
 */
int munmap(void *addr, size_t length)
{
	INIT(14);

	cf_atomic64_incr(&mem_count_munmaps);
	cf_atomic64_decr(&mem_count_net_mmaps);
	dfprintf(stderr, ">>>In asm munmap()<<<\n");

	int retval = original_munmap(addr, length);

	cf_atomic64_sub(&mem_count_munmap_total, length);
	cf_atomic64_sub(&mem_count_net_mmap_total, length);

	return retval;
}
#endif

/************************************ Sys V IPC - SHM ************************************/

/*
 *  ASM version of shmat(2).
 */
void *shmat(int shmid, const void *shmaddr, int shmflg)
{
	INIT(15);

	cf_atomic64_incr(&mem_count_shmats);
	dfprintf(stderr, ">>>In asm shmat()<<<\n");

	void *retval = original_shmat(shmid, shmaddr, shmflg);

	// XXX -- Should correctly modify shm accounting!

	return retval;
}

/*
 *  ASM version of shmctl(2).
 */
int shmctl(int shmid, int cmd, struct shmid_ds *buf)
{
	INIT(16);

	cf_atomic64_incr(&mem_count_shmctls);
	dfprintf(stderr, ">>>In asm shmctl()<<<\n");

	int retval = original_shmctl(shmid, cmd, buf);

	// XXX -- Should correctly modify shm accounting!

	return retval;
}

/*
 *  ASM version of shmdt(2).
 */
int shmdt(const void *shmaddr)
{
	INIT(17);

	cf_atomic64_incr(&mem_count_shmdts);
	dfprintf(stderr, ">>>In asm shmdt()<<<\n");

	int retval = original_shmdt(shmaddr);

	// XXX -- Should correctly modify shm accounting!

	return retval;
}

/*
 *  ASM version of shmget(2).
 */
int shmget(key_t key, size_t size, int shmflg)
{
	INIT(18);

	cf_atomic64_incr(&mem_count_shmgets);
	cf_atomic64_add(&mem_count_net_shm, size);
	dfprintf(stderr, ">>>In asm shmget()<<<\n");

	int retval = original_shmget(key, size, shmflg);

	return retval;
}
