CC ?= cc
CFLAGS ?= -O2
CPPFLAGS ?=
LDFLAGS ?=
LDLIBS ?= -lbpf
DESTDIR ?=
PREFIX ?= /usr

.PHONY: all clean install

all: client-access-bpfctl

client-access-bpfctl: client-access-bpfctl.c client-access-bpf.h
	$(CC) $(CPPFLAGS) $(CFLAGS) -Wall -Wextra -Werror -std=gnu11 \
		-o $@ client-access-bpfctl.c $(LDFLAGS) $(LDLIBS)

install: client-access-bpfctl
	install -d $(DESTDIR)$(PREFIX)/sbin
	install -m 0755 client-access-bpfctl $(DESTDIR)$(PREFIX)/sbin/client-access-bpfctl

clean:
	rm -f client-access-bpfctl
