CLANG     ?= clang
CC        ?= gcc
# -Werror: the tree is clean under both gcc and clang-21, so a new
# warning is a break rather than something to scroll past.
CFLAGS    := -O2 -g -Wall -Werror -Iinclude -Isrc/engine
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
	rm -f bfd_xdp.o bfd_loader bfd_tx $(ENGINE_OBJS) \
	      tests/unit/bfd_xdp_test.o

# Same flags as bfd_xdp.o, plus src/xdp on the include path so the
# wrapper picks up the identical headers. Test-only: never shipped,
# never loaded outside tests/unit/xdp_run.
tests/unit/bfd_xdp_test.o: tests/unit/bfd_xdp_test.c include/bfd_shared.h \
			   $(wildcard src/xdp/*.h)
	$(CLANG) $(BPFFLAGS) -c $< -o $@

# Headers shared between the unit harnesses. Neither rule picked these
# up before: fsm_run globs src/engine/*.h, xdp_run listed only
# bfd_shared.h, so editing a vector table rebuilt nothing and the suite
# ran stale against the old expectations.
TEST_HDRS := $(wildcard tests/unit/*.h)

tests/unit/xdp_run: tests/unit/xdp_run.c include/bfd_shared.h $(TEST_HDRS)
	$(CC) $(CFLAGS) $< -o $@ -lbpf

# The FSM table links against the real fsm.o with three stubs; no
# root, no BPF, no testbed.
tests/unit/fsm_run: tests/unit/fsm_run.c src/engine/fsm.o src/engine/log.o \
		    $(wildcard src/engine/*.h) $(TEST_HDRS)
	$(CC) $(CFLAGS) tests/unit/fsm_run.c src/engine/fsm.o src/engine/log.o -o $@

tests/unit/dp_run: tests/unit/dp_run.c src/engine/dplane.o src/engine/log.o \
		   src/engine/session.o src/engine/fsm.o $(wildcard src/engine/*.h)
	$(CC) $(CFLAGS) tests/unit/dp_run.c src/engine/dplane.o \
		src/engine/session.o src/engine/fsm.o src/engine/log.o -o $@

# The bffdp parser under libFuzzer. Needs clang, not $(CC): -fsanitize=
# fuzzer is not in gcc. Deliberately NOT part of `check` - a fuzz run is
# open-ended, and the enumerable edges are already dp_run's 11 cases.
#
#     make tests/unit/dp_fuzz
#     ./tests/unit/dp_fuzz -runs=100000 tests/unit/corpus/
FUZZ_CC ?= clang
FUZZ_FLAGS ?= -g -O1 -fsanitize=fuzzer,address,undefined

tests/unit/dp_fuzz: tests/unit/dp_fuzz.c $(wildcard src/engine/*.c) \
		    $(wildcard src/engine/*.h) $(TEST_HDRS)
	$(FUZZ_CC) $(FUZZ_FLAGS) -Iinclude -Isrc/engine \
		tests/unit/dp_fuzz.c src/engine/dplane.c src/engine/session.c \
		src/engine/fsm.c src/engine/log.c -o $@ -lbpf

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

# Layer 3 end-to-end on veth + netns. Needs root and pytest, and
# runs in seconds rather than milliseconds, so it is NOT in `check`.
# The userspace parity rig first: 24 cases, seconds, and the only
# coverage of the socket receive path where the inert IP_MINTTL and
# IPV6_MINHOPCOUNT fixes live. Needs no peer and no testbed, and was
# runnable all along without being gated by anything.
check-netns:
	python3 tests/netns_userspace.py
	python3 -m pytest tests/e2e -v -m "not frr"

# Layer 3 scenarios against stock FRR bfdd in containers. Separate from
# check-netns because it needs a container runtime and pulls a ~100MB
# image, which is a poor trade on every push against 30 cases that need
# nothing. BFD_CONTAINER_RUNTIME=docker on a runner, podman on the DUT.
check-frr:
	python3 -m pytest tests/e2e -v -m frr

test-fsm: tests/unit/fsm_run
	./tests/unit/fsm_run

# Needs root and the loaded object; not part of `all`.
#
# bfd_xdp_test.o is a prerequisite because xdp_run opens it by path at
# runtime: nothing else referred to it, so the rule below never fired and
# the sweep half of the suite ran against whatever bytecode was left on
# disk. Editing sweep.h then changed the program under test and not the
# object, which is the same stale-build trap the TEST_HDRS comment
# describes - and it hid a real behaviour change until the object was
# removed by hand.
test-xdp: tests/unit/xdp_run bfd_xdp.o tests/unit/bfd_xdp_test.o
	sudo ./tests/unit/xdp_run

.PHONY: all clean abi-check check test-xdp test-fsm test-dp check-netns check-frr
