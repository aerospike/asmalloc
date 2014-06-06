#
#  Makefile
#
#  This is the makefile for the ASMalloc memory allocation tracking tools.
#

# Define variables.

INCDIR = include
SRCDIR = src
OBJDIR = obj
LIBDIR = lib
BINDIR = bin

LIB_HEADERS = \
	$(INCDIR)/asmalloc.h \
	$(INCDIR)/vm_stats.h

LIB_SOURCES = \
	$(SRCDIR)/asmalloc.c \
	$(SRCDIR)/vm_stats.c

LIB_OBJECTS = $(LIB_SOURCES:$(SRCDIR)/%.c=$(OBJDIR)/%.o)

LIBRARY = $(LIBDIR)/asmalloc$(EXT).so

PRELOADS = $(LIBRARY)

JEM_LIBRARY = /usr/lib64/libjemalloc.so

PROGRAM_NAMES = test-asmalloc

PROGRAMS = $(PROGRAM_NAMES:%=$(BINDIR)/%$(EXT))

PGM_HEADERS = $(INCDIR)/test-mallocations.h

PGM_SOURCES = $(PROGRAM_NAMES:%=$(SRCDIR)/%.c)

PGM_OBJECTS = $(PGM_SOURCES:$(SRCDIR)/%.c=$(OBJDIR)/%.o)

HEADERS = $(LIB_HEADERS) $(PGM_HEADERS)

SOURCES = $(LIB_SOURCES) $(PGM_SOURCES)

OBJECTS = $(LIB_OBJECTS) $(PGM_OBJECTS)

# For GCC v4.4.5 use DWARF version 2, othewise use version 4:
ifeq ($(shell gcc -dumpversion), 4.4.5)
  DWARF_VERSION=2
else
  DWARF_VERSION=4
endif

CFLAGS = -gdwarf-$(DWARF_VERSION) -g3 -Wall -std=gnu99 -fPIC -I$(INCDIR)

ifneq ($(FOR_JEMALLOC),)
  CFLAGS += -DFOR_JEMALLOC
  EXT = .jem
  PRELOADS = $(LIBRARY):$(JEM_LIBRARY)
endif

LIB_LDFLAGS = -shared

PGM_LDFLAGS = -rdynamic

LIBRARIES = -ldl -lpthread -lrt

TARGETS = all clean cleaner cleanest test

TARGETS.JEM = $(TARGETS:%=%.jem)

# Define targets.

all:	clean $(LIBRARY) $(PROGRAMS)

jem:	all.jem

clean:
	$(RM) $(OBJECTS)

cleaner:	clean
	$(RM) $(PROGRAMS)

cleanest:	cleaner
	$(RM) $(LIBRARY)

test:	all
	LD_PRELOAD=$(PRELOADS) $(PROGRAMS)

$(TARGETS.JEM):
	$(MAKE) $(@:%.jem=%) FOR_JEMALLOC=1

$(SOURCES):	$(HEADERS)

$(LIBRARY):	$(LIB_OBJECTS)
	$(LINK.c) $(LIB_LDFLAGS) -o $@ $^ $(LIBRARIES)

$(PROGRAMS):	$(PGM_OBJECTS)
	$(LINK.c) $(PGM_LDFLAGS) -o $@ $^ $(LIBRARIES)

$(OBJDIR)/%.o:	$(SRCDIR)/%.c
	$(COMPILE.c) $< -o $@
