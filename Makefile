CLANG     ?= clang
CC        ?= gcc
CFLAGS    := -O2 -g -Wall -Iinclude
BPFFLAGS  := -O2 -g -Wall -target bpf -Iinclude -Isrc/xdp -I/usr/include/x86_64-linux-gnu

ENGINE_OBJS := bfd_tx.o

all: bfd_xdp.o bfd_loader bfd_tx

bfd_xdp.o: bfd_xdp.c include/bfd_shared.h $(wildcard src/xdp/*.h)
	$(CLANG) $(BPFFLAGS) -c $< -o $@

bfd_loader: loader.c include/bfd_shared.h
	$(CC) $(CFLAGS) $< -o $@ -lbpf

bfd_tx: $(ENGINE_OBJS)
	$(CC) $(CFLAGS) $^ -o $@ -lbpf

%.o: %.c include/bfd_shared.h
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f bfd_xdp.o bfd_loader bfd_tx $(ENGINE_OBJS)

.PHONY: all clean
