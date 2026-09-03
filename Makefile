CLANG     ?= clang
CC        ?= gcc
CFLAGS    := -O2 -g -Wall -Werror -Iinclude -Isrc/engine
# The BPF target has no multiarch include path of its own, so the system's
# triple supplies it. Not $(CC) -dumpmachine: the directory is a property
# of the system, not of the compiler, and clang and gcc name it
# differently for the same box.
TRIPLE    := $(shell dpkg-architecture -qDEB_HOST_MULTIARCH 2>/dev/null \
		     || gcc -dumpmachine)
BPFFLAGS  := -O2 -g -Wall -target bpf -Iinclude -Isrc/xdp -I/usr/include/$(TRIPLE)

ENGINE_OBJS := src/engine/log.o src/engine/main.o src/engine/session.o src/engine/dplane.o src/engine/ktx.o src/engine/echo_tx.o src/engine/fsm.o src/engine/stats.o

all: abi-check bfd_xdp.o bfd_loader bfd_tx

# Layout pins for the shared structs, checked by both compilers.
# Syntax-only: a divergence is a build error, there is nothing to run.
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

# Same flags and headers as bfd_xdp.o. Test-only: never shipped, never
# loaded outside tests/unit/xdp_run.
tests/unit/bfd_xdp_test.o: tests/unit/bfd_xdp_test.c include/bfd_shared.h \
			   $(wildcard src/xdp/*.h)
	$(CLANG) $(BPFFLAGS) -c $< -o $@

# Headers shared between the unit harnesses. Without these as
# prerequisites, editing a vector table rebuilds nothing and the suites
# run stale against the old expectations.
TEST_HDRS := $(wildcard tests/unit/*.h)

tests/unit/xdp_run: tests/unit/xdp_run.c include/bfd_shared.h $(TEST_HDRS)
	$(CC) $(CFLAGS) $< -o $@ -lbpf

# Links against the real fsm.o with three stubs; no root, no BPF.
tests/unit/fsm_run: tests/unit/fsm_run.c src/engine/fsm.o src/engine/log.o \
		    $(wildcard src/engine/*.h) $(TEST_HDRS)
	$(CC) $(CFLAGS) tests/unit/fsm_run.c src/engine/fsm.o src/engine/log.o -o $@

tests/unit/dp_run: tests/unit/dp_run.c src/engine/dplane.o src/engine/log.o \
		   src/engine/session.o src/engine/fsm.o $(wildcard src/engine/*.h)
	$(CC) $(CFLAGS) tests/unit/dp_run.c src/engine/dplane.o \
		src/engine/session.o src/engine/fsm.o src/engine/log.o -o $@

# The bffdp parser under libFuzzer. Needs clang, not $(CC): gcc has no
# -fsanitize=fuzzer. Not part of `check` - a fuzz run is open-ended, and
# the enumerable edges are already covered by dp_run.
#
#     make tests/unit/dp_fuzz
#     ./tests/unit/dp_fuzz -runs=100000 corpus/
FUZZ_CC ?= clang
FUZZ_FLAGS ?= -g -O1 -fsanitize=fuzzer,address,undefined

tests/unit/dp_fuzz: tests/unit/dp_fuzz.c $(wildcard src/engine/*.c) \
		    $(wildcard src/engine/*.h) $(TEST_HDRS)
	$(FUZZ_CC) $(FUZZ_FLAGS) -Iinclude -Isrc/engine \
		tests/unit/dp_fuzz.c src/engine/dplane.c src/engine/session.c \
		src/engine/fsm.c src/engine/log.c -o $@ -lbpf

test-dp: tests/unit/dp_run
	./tests/unit/dp_run

# Everything that runs without a testbed. Ordered cheapest and least
# privileged first, so a developer without sudo still gets three suites
# and a clear failure on the fourth.
check: all test-fsm test-dp test-xdp
	@echo "all suites passed"

# End-to-end on veth and network namespaces. Needs root and pytest, and
# takes seconds rather than milliseconds, so it is not in `check`. The
# parity rig runs first: it is the only coverage of the socket receive
# path, where GTSM is enforced by IP_MINTTL and IPV6_MINHOPCOUNT.
check-netns:
	python3 tests/netns_userspace.py
	python3 -m pytest tests/e2e -v -m "not frr"

# Scenarios against stock FRR bfdd in containers. Separate from
# check-netns because it needs a container runtime and a ~100MB image.
# Set BFD_CONTAINER_RUNTIME to docker or podman.
check-frr:
	python3 -m pytest tests/e2e -v -m frr

test-fsm: tests/unit/fsm_run
	./tests/unit/fsm_run

# Needs root to load the object; not part of `all`. bfd_xdp_test.o is a
# prerequisite because xdp_run opens it by path at runtime - without it
# the sweep half of the suite runs against stale bytecode.
test-xdp: tests/unit/xdp_run bfd_xdp.o tests/unit/bfd_xdp_test.o
	sudo ./tests/unit/xdp_run

.PHONY: all clean abi-check check test-xdp test-fsm test-dp check-netns check-frr
