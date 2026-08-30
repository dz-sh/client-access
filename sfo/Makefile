CC ?= cc
CFLAGS ?= -O2
CPPFLAGS ?=
LDFLAGS ?=
LDLIBS ?= -lbpf -lnetfilter_conntrack

.PHONY: all clean

all: client-access-sfoctl

client-access-sfoctl: client-access-sfoctl.c client-access-bpf.h
	$(CC) $(CPPFLAGS) $(CFLAGS) -Wall -Wextra -Werror -std=gnu11 \
		-o $@ client-access-sfoctl.c $(LDFLAGS) $(LDLIBS)

clean:
	rm -f client-access-sfoctl
