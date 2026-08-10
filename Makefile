CLANG     ?= clang
CC        ?= gcc
CFLAGS    := -O2 -g -Wall -Iinclude -Isrc/engine
BPFFLAGS  := -O2 -g -Wall -target bpf -Iinclude -Isrc/xdp -I/usr/include/x86_64-linux-gnu

ENGINE_OBJS := src/engine/main.o src/engine/session.o src/engine/dplane.o src/engine/ktx.o src/engine/echo_tx.o src/engine/fsm.o

all: bfd_xdp.o bfd_loader bfd_tx

bfd_xdp.o: bfd_xdp.c include/bfd_shared.h $(wildcard src/xdp/*.h)
	$(CLANG) $(BPFFLAGS) -c $< -o $@

bfd_loader: src/loader/bfd_loader.c include/bfd_shared.h
	$(CC) $(CFLAGS) $< -o $@ -lbpf

bfd_tx: $(ENGINE_OBJS)
	$(CC) $(CFLAGS) $^ -o $@ -lbpf

%.o: %.c include/bfd_shared.h $(wildcard src/engine/*.h)
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f bfd_xdp.o bfd_loader bfd_tx $(ENGINE_OBJS)

.PHONY: all clean
