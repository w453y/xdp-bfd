CLANG     ?= clang
CC        ?= gcc
CFLAGS    := -O2 -g -Wall -Iinclude -Isrc/engine
# The BPF target has no multiarch include path of its own, so the
# system's triple supplies it. Hardcoding x86_64-linux-gnu broke any
# other architecture.
#
# Not $(CC) -dumpmachine: the multiarch directory is a property of the
# system, not of whichever compiler is building. gcc says
# x86_64-linux-gnu and clang says x86_64-pc-linux-gnu for the same box,
# so CC=clang pointed -I at a directory that does not exist and every
# build failed on <asm/types.h>. dpkg-architecture is authoritative
# where it exists; gcc's answer is the fallback.
TRIPLE    := $(shell dpkg-architecture -qDEB_HOST_MULTIARCH 2>/dev/null \
		     || gcc -dumpmachine)
BPFFLAGS  := -O2 -g -Wall -target bpf -Iinclude -Isrc/xdp -I/usr/include/$(TRIPLE)

ENGINE_OBJS := src/engine/log.o src/engine/main.o src/engine/session.o src/engine/dplane.o src/engine/ktx.o src/engine/echo_tx.o src/engine/fsm.o src/engine/stats.o

all: abi-check bfd_xdp.o bfd_loader bfd_tx

# Layout pins for the shared structs, checked by both compilers.
# Syntax-only: there is nothing to run, a divergence is a build error.
abi-check: tests/unit/abi_check.c include/bfd_shared.h
	$(CC) $(CFLAGS) -fsyntax-only $<
	$(CLANG) $(BPFFLAGS) -fsyntax-only $<

bfd_xdp.o: src/xdp/bfd_xdp.c include/bfd_shared.h $(wildcard src/xdp/*.h)
	$(CLANG) $(BPFFLAGS) -c $< -o $@

bfd_loader: src/loader/bfd_loader.c include/bfd_shared.h
	$(CC) $(CFLAGS) $< -o $@ -lbpf

bfd_tx: $(ENGINE_OBJS)
	$(CC) $(CFLAGS) $^ -o $@ -lbpf

%.o: %.c include/bfd_shared.h $(wildcard src/engine/*.h)
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f bfd_xdp.o bfd_loader bfd_tx $(ENGINE_OBJS)

# Same flags as bfd_xdp.o, plus src/xdp on the include path so the
# wrapper picks up the identical headers. Test-only: never shipped,
# never loaded outside tests/unit/xdp_run.
tests/unit/bfd_xdp_test.o: tests/unit/bfd_xdp_test.c include/bfd_shared.h \
			   $(wildcard src/xdp/*.h)
	$(CLANG) $(BPFFLAGS) -c $< -o $@

tests/unit/xdp_run: tests/unit/xdp_run.c include/bfd_shared.h
	$(CC) $(CFLAGS) $< -o $@ -lbpf

# The FSM table links against the real fsm.o with three stubs; no
# root, no BPF, no testbed.
tests/unit/fsm_run: tests/unit/fsm_run.c src/engine/fsm.o src/engine/log.o \
		    $(wildcard src/engine/*.h)
	$(CC) $(CFLAGS) tests/unit/fsm_run.c src/engine/fsm.o src/engine/log.o -o $@

tests/unit/dp_run: tests/unit/dp_run.c src/engine/dplane.o src/engine/log.o \
		   src/engine/session.o src/engine/fsm.o $(wildcard src/engine/*.h)
	$(CC) $(CFLAGS) tests/unit/dp_run.c src/engine/dplane.o \
		src/engine/session.o src/engine/fsm.o src/engine/log.o -o $@

test-dp: tests/unit/dp_run
	./tests/unit/dp_run

# Everything that can run without a testbed, in one command.
#
# Ordered cheapest and least privileged first: abi-check is part of
# `all`, fsm and dp need no root, and test-xdp needs it to load the
# object. A developer without sudo still gets three suites and a
# clear failure on the fourth rather than nothing at all.
check: all test-fsm test-dp test-xdp
	@echo "all suites passed"

test-fsm: tests/unit/fsm_run
	./tests/unit/fsm_run

# Needs root and the loaded object; not part of `all`.
test-xdp: tests/unit/xdp_run bfd_xdp.o
	sudo ./tests/unit/xdp_run

.PHONY: all clean abi-check check test-xdp test-fsm test-dp
