CLANG     ?= clang
CC        ?= gcc
WERROR    ?= -Werror
# CFLAGS takes a distro build's codegen and hardening flags; our includes and
# defines live in XDP_CFLAGS, and LDFLAGS applies to the userspace links. None
# of it reaches the BPF object. A package build may pass WERROR= if injected
# flags trip -Werror.
XDP_CFLAGS := -O2 -g -Wall $(WERROR) -Iinclude -Isrc/engine

# Install layout, overridable by the package build. BFD_XDP_OBJDIR tells the
# binary where the object is installed; VERSION is stamped into --version.
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
# The BPF target needs the system's multiarch include directory.
TRIPLE    := $(shell dpkg-architecture -qDEB_HOST_MULTIARCH 2>/dev/null \
		     || gcc -dumpmachine)
BPFFLAGS  := -O2 -g -Wall -target bpf -Iinclude -Isrc/xdp -I/usr/include/$(TRIPLE)

# The object's install location and the version, compiled into the C side.
# Harmless in a build-tree run: objpath tries beside-the-binary first.
XDP_CFLAGS += -DBFD_XDP_OBJDIR='"$(LIBDIR)"' -DBFD_XDP_VERSION='"$(VERSION)"'

# Every shared header, so a change to any rebuilds both planes.
SHARED_HDRS := $(wildcard include/*.h)

ENGINE_OBJS := src/engine/log.o src/engine/main.o src/engine/session.o src/engine/dplane.o src/engine/ktx.o src/engine/echo_tx.o src/engine/fsm.o src/engine/stats.o src/engine/rx.o src/engine/ktx_cfg.o \
	       src/engine/opts.o src/engine/sock.o src/engine/static.o \
	       src/engine/dplane_conn.o src/engine/ktx_load.o

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
	$(INSTALL) -m 0644 packaging/xdp-bfd-observe.8 $(DESTDIR)$(MANDIR)/xdp-bfd-observe.8

# Layout pins for the shared structs, checked by both compilers.
# Syntax-only: a divergence is a build error, there is nothing to run.
abi-check: tests/unit/abi_check.c $(SHARED_HDRS)
	$(CC) $(CFLAGS) $(CPPFLAGS) $(XDP_CFLAGS) -fsyntax-only $<
	$(CLANG) $(BPFFLAGS) -fsyntax-only $<

bfd_xdp.o: src/xdp/bfd_xdp.c $(SHARED_HDRS) $(wildcard src/xdp/*.h)
	$(CLANG) $(BPFFLAGS) -c $< -o $@

bfd_loader: src/loader/bfd_loader.c $(SHARED_HDRS)
	$(CC) $(CFLAGS) $(CPPFLAGS) $(XDP_CFLAGS) $< -o $@ $(LDFLAGS) -lbpf

bfd_tx: $(ENGINE_OBJS)
	$(CC) $(CFLAGS) $(XDP_CFLAGS) $^ -o $@ $(LDFLAGS) -lbpf

%.o: %.c $(SHARED_HDRS) $(wildcard src/engine/*.h)
	$(CC) $(CFLAGS) $(CPPFLAGS) $(XDP_CFLAGS) -c $< -o $@

clean:
	rm -f bfd_xdp.o bfd_loader bfd_tx $(ENGINE_OBJS) \
	      tests/unit/bfd_xdp_test.o tests/unit/hmac_run \
	      tests/unit/xdp_run tests/unit/fsm_run tests/unit/dp_run \
	      tests/unit/rx_run tests/unit/ktx_cfg_run \
	      tests/unit/dp_fuzz

# Same flags and headers as bfd_xdp.o. Test-only: never shipped, never
# loaded outside tests/unit/xdp_run.
tests/unit/bfd_xdp_test.o: tests/unit/bfd_xdp_test.c $(SHARED_HDRS) \
			   $(wildcard src/xdp/*.h)
	$(CLANG) $(BPFFLAGS) -c $< -o $@

# Headers shared between the unit harnesses, as prerequisites.
TEST_HDRS := $(wildcard tests/unit/*.h)

tests/unit/xdp_run: tests/unit/xdp_run.c $(wildcard tests/unit/xdp/*.c) $(SHARED_HDRS) $(TEST_HDRS)
	$(CC) $(CFLAGS) $(XDP_CFLAGS) -Itests/unit $< -o $@ -lbpf

# Links against the real fsm.o with four stubs; no root, no BPF.
tests/unit/fsm_run: tests/unit/fsm_run.c $(wildcard tests/unit/fsm/*.c) \
		    src/engine/fsm.o src/engine/log.o $(wildcard src/engine/*.h) $(TEST_HDRS)
	$(CC) $(CFLAGS) $(XDP_CFLAGS) tests/unit/fsm_run.c src/engine/fsm.o src/engine/log.o -o $@

# ktx_cfg_for, without a loaded program.
tests/unit/ktx_cfg_run: tests/unit/ktx_cfg_run.c src/engine/ktx_cfg.o \
			src/engine/log.o $(wildcard src/engine/*.h) $(TEST_HDRS)
	$(CC) $(CFLAGS) $(XDP_CFLAGS) tests/unit/ktx_cfg_run.c \
		src/engine/ktx_cfg.o src/engine/log.o -o $@

# rx_accept against the session table; no sockets or root.
tests/unit/rx_run: tests/unit/rx_run.c src/engine/rx.o src/engine/session.o \
		   src/engine/log.o $(wildcard src/engine/*.h) $(TEST_HDRS)
	$(CC) $(CFLAGS) $(XDP_CFLAGS) tests/unit/rx_run.c src/engine/rx.o \
		src/engine/session.o src/engine/log.o -o $@

tests/unit/dp_run: tests/unit/dp_run.c $(wildcard tests/unit/dp/*.c) \
		   src/engine/dplane.o src/engine/dplane_conn.o src/engine/log.o \
		   src/engine/session.o src/engine/fsm.o $(wildcard src/engine/*.h) \
		   $(TEST_HDRS)
	$(CC) $(CFLAGS) $(XDP_CFLAGS) tests/unit/dp_run.c src/engine/dplane.o \
		src/engine/dplane_conn.o src/engine/session.o src/engine/fsm.o \
		src/engine/log.o -o $@

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
		tests/unit/dp_fuzz.c src/engine/dplane.c src/engine/dplane_conn.c src/engine/session.c \
		src/engine/fsm.c src/engine/log.c -o $@

# The XDP program under libFuzzer. Drives bfd_xdp.o with BPF_PROG_TEST_RUN,
# so it needs libbpf and root; not part of `check`.
#
#     make FUZZ_CC=clang-21 tests/unit/xdp_fuzz
#     sudo ./tests/unit/xdp_fuzz -runs=200000 corpus/
tests/unit/xdp_fuzz: tests/unit/xdp_fuzz.c include/bfd_shared.h bfd_xdp.o
	$(FUZZ_CC) $(FUZZ_FLAGS) -Iinclude -Isrc/xdp \
		tests/unit/xdp_fuzz.c -o $@ -lbpf

test-dp: tests/unit/dp_run
	./tests/unit/dp_run

test-rx: tests/unit/rx_run
	./tests/unit/rx_run

test-ktxcfg: tests/unit/ktx_cfg_run
	./tests/unit/ktx_cfg_run

# What a contributor with nothing installed can run: no libbpf, no root, no
# NIC; clang only for abi-check's syntax pass.
check-host: abi-check test-hmac test-fsm test-dp test-rx test-ktxcfg
	@echo "host suites passed"

# Everything that runs without a testbed, which is the above plus the XDP
# program itself. Ordered cheapest and least privileged first, so a failure
# arrives before the parts that need root.
check: check-host all test-xdp
	@echo "all suites passed"

# End-to-end on veth and network namespaces; needs root and pytest. The parity
# rig covers the socket receive path.
check-netns:
	python3 tests/testbed/netns_userspace.py
	python3 -m pytest tests/e2e -v -m "not frr"

# Scenarios against stock FRR bfdd in containers. Separate from
# check-netns because it needs a container runtime and a ~200MB image.
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

# Loads the program through BPF_PROG_TEST_RUN, so run as `sudo make test-xdp`.
# bfd_xdp_test.o is a prerequisite because xdp_run opens it at runtime.
test-xdp: tests/unit/xdp_run bfd_xdp.o tests/unit/bfd_xdp_test.o
	./tests/unit/xdp_run

.PHONY: all install clean abi-check check check-host test-xdp test-fsm test-dp test-hmac check-netns check-frr test-rx test-ktxcfg
