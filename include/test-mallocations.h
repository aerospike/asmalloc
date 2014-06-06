/*
 * include/test-mallocations.h
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
 *    Sample database of (fictitious) memory allocation function call locations
 *    in the application.  This file defines types and a statically-initialized
 *    table giving the info. about each memory allocation-related function call
 *    in the application source code.  Ideally, the actual table would be
 *    automatically re-generated whenever the application source code is modified.
 *    This is part of the ASMalloc memory allocation tracking tool package.
 */

#pragma once

typedef enum mallocation_type_e {
	MALLOCATION_TYPE_NONE,
	MALLOCATION_TYPE_REALLOC,
	MALLOCATION_TYPE_FREE,
	MALLOCATION_TYPE_CALLOC,
	MALLOCATION_TYPE_VALLOC,
	MALLOCATION_TYPE_STRDUP,
	MALLOCATION_TYPE_STRNDUP,
	MALLOCATION_TYPE_MALLOC,
} mallocation_type_t;

char *mallocation_type_names[] = {
	"MALLOCATION_TYPE_NONE",
	"MALLOCATION_TYPE_REALLOC",
	"MALLOCATION_TYPE_FREE",
	"MALLOCATION_TYPE_CALLOC",
	"MALLOCATION_TYPE_VALLOC",
	"MALLOCATION_TYPE_STRDUP",
	"MALLOCATION_TYPE_STRNDUP",
	"MALLOCATION_TYPE_MALLOC",
};

typedef struct mallocation_s {
	mallocation_type_t type;
	char *file;
	int line;
	int id;
} mallocation_t;

#define  NUM_MALLOCATIONS  (7)

mallocation_t mallocations[NUM_MALLOCATIONS] = {
	{ MALLOCATION_TYPE_NONE,    "",          0, 0 }, /* Non-existent mallocation. */
	{ MALLOCATION_TYPE_CALLOC,  "test1.c", 101, 1 },
	{ MALLOCATION_TYPE_FREE,    "test2.c", 202, 2 },
	{ MALLOCATION_TYPE_MALLOC,  "test3.c", 303, 3 },
	{ MALLOCATION_TYPE_REALLOC, "test4.c", 404, 4 },
	{ MALLOCATION_TYPE_STRDUP,  "test5.c", 505, 5 },
	{ MALLOCATION_TYPE_VALLOC,  "test6.c", 606, 6 }
};
