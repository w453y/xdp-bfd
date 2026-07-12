CLANG   ?= clang
CC      ?= gcc
CFLAGS  := -O2 -g -Wall -Iinclude

all: bfd_xdp.o bfd_loader

bfd_xdp.o: bfd_xdp.c include/bfd_shared.h
	$(CLANG) -O2 -g -Wall -target bpf -Iinclude -I/usr/include/x86_64-linux-gnu -c $< -o $@

bfd_loader: loader.c include/bfd_shared.h
	$(CC) $(CFLAGS) $< -o $@ -lbpf

clean:
	rm -f bfd_xdp.o bfd_loader

.PHONY: all clean

bfd_tx: bfd_tx.c include/bfd_shared.h
	$(CC) $(CFLAGS) bfd_tx.c -o bfd_tx -lbpf
