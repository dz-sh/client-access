CC ?= cc
CFLAGS ?= -O2
CPPFLAGS ?=
LDFLAGS ?=
LDLIBS ?= -lbpf
DESTDIR ?=
PREFIX ?= /usr

.PHONY: all clean install

BPFCTL_SOURCES := client-access-bpfctl.c bpfctl-common.c bpf-object.c \
	bpf-tc.c bpf-snapshot.c bpf-runtime.c bpf-health.c
BPFCTL_HEADERS := client-access-bpf.h bpfctl-internal.h

all: client-access-bpfctl

client-access-bpfctl: $(BPFCTL_SOURCES) $(BPFCTL_HEADERS)
	$(CC) $(CPPFLAGS) $(CFLAGS) -Wall -Wextra -Werror -std=gnu11 \
		-o $@ $(BPFCTL_SOURCES) $(LDFLAGS) $(LDLIBS)

install: client-access-bpfctl
	install -d $(DESTDIR)$(PREFIX)/sbin
	install -m 0755 client-access-bpfctl $(DESTDIR)$(PREFIX)/sbin/client-access-bpfctl

clean:
	rm -f client-access-bpfctl
