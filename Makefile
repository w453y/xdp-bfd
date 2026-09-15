CLANG     ?= clang
CC        ?= gcc
WERROR    ?= -Werror
# CFLAGS is the injectable slot: a distro package build layers its codegen
# and hardening flags into it (dpkg-buildflags, Fedora %{optflags}) without
# wiping our include paths and -D defines, which live in XDP_CFLAGS and are
# always applied to the userspace build. $(LDFLAGS) is honoured on the two
# userspace link lines for RELRO and PIE. None of this reaches the BPF
# object: BPFFLAGS and the bfd_xdp.o rule are left untouched, so x86 codegen
# hardening (meaningless or breaking under clang -target bpf) never lands on
# it. WERROR is separated so a package build may pass WERROR= if a distro's
# injected flags trip -Werror; it stays on for the normal build.
XDP_CFLAGS := -O2 -g -Wall $(WERROR) -Iinclude -Isrc/engine

# Install layout, overridable by the package build. The object goes to
# LIBDIR and the binary is told where with -DBFD_XDP_OBJDIR so it finds it
# once installed away from its build directory. VERSION is stamped into
# --version; the package build passes the real one.
PREFIX  ?= /usr
SBINDIR ?= $(PREFIX)/sbin
LIBDIR  ?= $(PREFIX)/lib/xdp-bfd
UNITDIR ?= $(PREFIX)/lib/systemd/system
SYSCTLDIR ?= $(PREFIX)/lib/sysctl.d
SYSCONFDIR ?= /etc
DOCDIR  ?= $(PREFIX)/share/doc/xdp-bfd
MANDIR  ?= $(PREFIX)/share/man/man8
VERSION ?= 0.0.0-dev
INSTALL ?= install
# The BPF target has no multiarch include path of its own, so the system's
# triple supplies it. Not $(CC) -dumpmachine: the directory is a property
# of the system, not of the compiler, and clang and gcc name it
# differently for the same box.
TRIPLE    := $(shell dpkg-architecture -qDEB_HOST_MULTIARCH 2>/dev/null \
		     || gcc -dumpmachine)
BPFFLAGS  := -O2 -g -Wall -target bpf -Iinclude -Isrc/xdp -I/usr/include/$(TRIPLE)

# The object's install location and the version, compiled into the C side.
# Harmless in a build-tree run: objpath tries beside-the-binary first.
XDP_CFLAGS += -DBFD_XDP_OBJDIR='"$(LIBDIR)"' -DBFD_XDP_VERSION='"$(VERSION)"'

# Every shared header, not one named by hand. include/ grew a digest and
# an authentication layout that both planes compile, and a rule naming
# only bfd_shared.h rebuilds neither when they change - the object then
# disagrees with the source that produced it, silently.
SHARED_HDRS := $(wildcard include/*.h)

ENGINE_OBJS := src/engine/log.o src/engine/main.o src/engine/session.o src/engine/dplane.o src/engine/ktx.o src/engine/echo_tx.o src/engine/fsm.o src/engine/stats.o

all: abi-check bfd_xdp.o bfd_loader bfd_tx

# The binary is installed as xdp-bfd and the loader as xdp-bfd-observe, the
# names the package and the systemd unit use; bfd_tx / bfd_loader are the
# build-tree names. DESTDIR for staged packaging, PREFIX for the prefix.
install: all
	$(INSTALL) -d $(DESTDIR)$(SBINDIR) $(DESTDIR)$(LIBDIR)
	$(INSTALL) -m 0755 bfd_tx     $(DESTDIR)$(SBINDIR)/xdp-bfd
	$(INSTALL) -m 0755 bfd_loader $(DESTDIR)$(SBINDIR)/xdp-bfd-observe
	$(INSTALL) -m 0644 bfd_xdp.o  $(DESTDIR)$(LIBDIR)/bfd_xdp.o
	$(INSTALL) -d $(DESTDIR)$(UNITDIR) $(DESTDIR)$(SYSCTLDIR)
	$(INSTALL) -m 0644 packaging/xdp-bfd.service $(DESTDIR)$(UNITDIR)/xdp-bfd.service
	$(INSTALL) -m 0644 packaging/50-xdp-bfd.conf  $(DESTDIR)$(SYSCTLDIR)/50-xdp-bfd.conf
	$(INSTALL) -d $(DESTDIR)$(SYSCONFDIR)/xdp-bfd
	$(INSTALL) -m 0644 packaging/engine.conf $(DESTDIR)$(SYSCONFDIR)/xdp-bfd/engine.conf
	$(INSTALL) -d $(DESTDIR)$(DOCDIR) $(DESTDIR)$(DOCDIR)/examples
	$(INSTALL) -m 0644 README.md $(DESTDIR)$(DOCDIR)/README.md
	$(INSTALL) -m 0644 packaging/frr-daemons.snippet $(DESTDIR)$(DOCDIR)/examples/frr-daemons.snippet
	$(INSTALL) -d $(DESTDIR)$(MANDIR)
	$(INSTALL) -m 0644 packaging/xdp-bfd.8 $(DESTDIR)$(MANDIR)/xdp-bfd.8

# Layout pins for the shared structs, checked by both compilers.
# Syntax-only: a divergence is a build error, there is nothing to run.
abi-check: tests/unit/abi_check.c $(SHARED_HDRS)
	$(CC) $(CFLAGS) $(XDP_CFLAGS) -fsyntax-only $<
	$(CLANG) $(BPFFLAGS) -fsyntax-only $<

bfd_xdp.o: src/xdp/bfd_xdp.c $(SHARED_HDRS) $(wildcard src/xdp/*.h)
	$(CLANG) $(BPFFLAGS) -c $< -o $@

bfd_loader: src/loader/bfd_loader.c $(SHARED_HDRS)
	$(CC) $(CFLAGS) $(XDP_CFLAGS) $< -o $@ $(LDFLAGS) -lbpf

bfd_tx: $(ENGINE_OBJS)
	$(CC) $(CFLAGS) $(XDP_CFLAGS) $^ -o $@ $(LDFLAGS) -lbpf

%.o: %.c $(SHARED_HDRS) $(wildcard src/engine/*.h)
	$(CC) $(CFLAGS) $(XDP_CFLAGS) -c $< -o $@

clean:
	rm -f bfd_xdp.o bfd_loader bfd_tx $(ENGINE_OBJS) \
	      tests/unit/bfd_xdp_test.o tests/unit/hmac_run \
	      tests/unit/xdp_run tests/unit/fsm_run tests/unit/dp_run \
	      tests/unit/dp_fuzz

# Same flags and headers as bfd_xdp.o. Test-only: never shipped, never
# loaded outside tests/unit/xdp_run.
tests/unit/bfd_xdp_test.o: tests/unit/bfd_xdp_test.c $(SHARED_HDRS) \
			   $(wildcard src/xdp/*.h)
	$(CLANG) $(BPFFLAGS) -c $< -o $@

# Headers shared between the unit harnesses. Without these as
# prerequisites, editing a vector table rebuilds nothing and the suites
# run stale against the old expectations.
TEST_HDRS := $(wildcard tests/unit/*.h)

tests/unit/xdp_run: tests/unit/xdp_run.c $(SHARED_HDRS) $(TEST_HDRS)
	$(CC) $(CFLAGS) $(XDP_CFLAGS) -Itests/unit $< -o $@ -lbpf

# Links against the real fsm.o with three stubs; no root, no BPF.
tests/unit/fsm_run: tests/unit/fsm_run.c src/engine/fsm.o src/engine/log.o \
		    $(wildcard src/engine/*.h) $(TEST_HDRS)
	$(CC) $(CFLAGS) $(XDP_CFLAGS) tests/unit/fsm_run.c src/engine/fsm.o src/engine/log.o -o $@

tests/unit/dp_run: tests/unit/dp_run.c src/engine/dplane.o src/engine/log.o \
		   src/engine/session.o src/engine/fsm.o $(wildcard src/engine/*.h) \
		   $(TEST_HDRS)
	$(CC) $(CFLAGS) $(XDP_CFLAGS) tests/unit/dp_run.c src/engine/dplane.o \
		src/engine/session.o src/engine/fsm.o src/engine/log.o -o $@

# The bfddp parser under libFuzzer. Needs clang, not $(CC): gcc has no
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
		src/engine/fsm.c src/engine/log.c -o $@

test-dp: tests/unit/dp_run
	./tests/unit/dp_run

# What a contributor with nothing installed can run: no libbpf, no clang
# beyond the one abi-check needs for its syntax pass, no root, no NIC.
#
# This exists because `check` depended on `all`, and `all` builds the BPF
# object and links two binaries against libbpf, so someone without
# libbpf-dev got none of it - not even the digest vectors or the state
# machine table, which need neither. The whole of check-host runs in about
# three seconds from cold.
check-host: abi-check test-hmac test-fsm test-dp
	@echo "host suites passed"

# Everything that runs without a testbed, which is the above plus the XDP
# program itself. Ordered cheapest and least privileged first, so a failure
# arrives before the parts that need root.
check: check-host all test-xdp
	@echo "all suites passed"

# End-to-end on veth and network namespaces. Needs root and pytest, and
# takes seconds rather than milliseconds, so it is not in `check`. The
# parity rig runs first: it is the only coverage of the socket receive
# path, where GTSM is enforced by IP_MINTTL and IPV6_MINHOPCOUNT.
check-netns:
	python3 tests/testbed/netns_userspace.py
	python3 -m pytest tests/e2e -v -m "not frr"

# Scenarios against stock FRR bfdd in containers. Separate from
# check-netns because it needs a container runtime and a ~100MB image.
# Set BFD_CONTAINER_RUNTIME to docker or podman.
check-frr:
	python3 -m pytest tests/e2e -v -m frr

test-fsm: tests/unit/fsm_run
	./tests/unit/fsm_run

# The shared digest on the host. The same vectors go through the kernel
# in test-xdp; this one needs neither root nor BPF.
tests/unit/hmac_run: tests/unit/hmac_run.c $(SHARED_HDRS) $(TEST_HDRS)
	$(CC) $(CFLAGS) $(XDP_CFLAGS) -Itests/unit $< -o $@

test-hmac: tests/unit/hmac_run
	./tests/unit/hmac_run

# Needs root to load the object; not part of `all`. bfd_xdp_test.o is a
# prerequisite because xdp_run opens it by path at runtime - without it
# the sweep half of the suite runs against stale bytecode.
# Needs root, because it loads the program through BPF_PROG_TEST_RUN.
# Invoked as `sudo make test-xdp`, like check-netns and check-frr, rather
# than reaching for sudo from inside a recipe: a Makefile that escalates on
# its own gives a contributor no way to run the rest without it, and it is
# why `make check` prompted for a password on a tree that had not built yet.
test-xdp: tests/unit/xdp_run bfd_xdp.o tests/unit/bfd_xdp_test.o
	./tests/unit/xdp_run

.PHONY: all install clean abi-check check check-host test-xdp test-fsm test-dp test-hmac check-netns check-frr
