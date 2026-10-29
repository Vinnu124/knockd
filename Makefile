# ──────────────────────────────────────────────────────────────────────
# knockd — port knocking daemon
#
#   make              build
#   make debug        no optimization, symbols, ASan + UBSan
#   make strict       build with the full warning set and -Werror (CI)
#   make test         build and run the unit tests
#   make install      install the binary, config and unit file
#   make uninstall    remove them again (keeps /etc/knockd.conf)
#   make clean
#
# Honours CC, CFLAGS, LDFLAGS, DESTDIR and PREFIX.
# ──────────────────────────────────────────────────────────────────────

CC         ?= gcc
PREFIX     ?= /usr/local
BINDIR     ?= $(PREFIX)/bin
SYSCONFDIR ?= /etc
UNITDIR    ?= $(SYSCONFDIR)/systemd/system

TARGET   = knockd
BUILDDIR = build

# Compiled in so `knockd --version` and the log match the tag that was
# built, with a fallback for a tarball that has no git metadata.
VERSION ?= $(shell git describe --tags --dirty 2>/dev/null || echo unknown)

SRCS = src/main.c src/sniffer.c src/knocker.c src/firewall.c \
       src/logger.c src/packet_queue.c src/config.c
OBJS = $(SRCS:src/%.c=$(BUILDDIR)/%.o)
DEPS = $(OBJS:.o=.d)

# Objects every test links against (everything but the daemon's main).
LIBOBJS   = $(filter-out $(BUILDDIR)/main.o,$(OBJS))
TEST_SRCS = $(wildcard tests/test_*.c)
TEST_BINS = $(TEST_SRCS:tests/%.c=$(BUILDDIR)/%)

WARNINGS = -Wall -Wextra

# Extra warnings worth fixing but not worth breaking someone's build over,
# so they live in `make strict` and in CI rather than in the default build.
STRICT_WARNINGS = -Wshadow -Wstrict-prototypes -Wmissing-prototypes \
                  -Wpointer-arith -Werror

# knockd runs as root, so the usual hardening is not optional.
# _FORTIFY_SOURCE is undefined first because some distributions predefine
# it, and redefining a macro is itself a warning.
HARDENING   = -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=2 \
              -fstack-protector-strong -fPIE
LDHARDENING = -pie -Wl,-z,relro -Wl,-z,now

BASEFLAGS = -std=c11 -D_GNU_SOURCE -I include -MMD -MP \
            -DKNOCKD_VERSION='"$(VERSION)"' -pthread
CFLAGS   ?= -O2
ALLCFLAGS = $(BASEFLAGS) $(WARNINGS) $(HARDENING) $(CFLAGS) $(EXTRA_CFLAGS)
ALLLDFLAGS = $(LDHARDENING) $(LDFLAGS)
LDLIBS    = -pthread

.PHONY: all debug strict test install uninstall clean

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) -o $@ $(OBJS) $(ALLLDFLAGS) $(LDLIBS)
	@echo "  built $(TARGET) $(VERSION)"

$(BUILDDIR)/%.o: src/%.c | $(BUILDDIR)
	$(CC) $(ALLCFLAGS) -c -o $@ $<

$(BUILDDIR):
	@mkdir -p $(BUILDDIR)

# Sanitizers catch the memory and threading mistakes that a daemon parsing
# attacker-supplied packets can least afford.
debug:
	$(MAKE) clean
	$(MAKE) CFLAGS="-O0 -g3 -fsanitize=address,undefined" \
	        LDFLAGS="-fsanitize=address,undefined" \
	        HARDENING="-fstack-protector-strong -fPIE"

strict:
	$(MAKE) clean
	$(MAKE) EXTRA_CFLAGS="$(STRICT_WARNINGS)"

# ── Tests ────────────────────────────────────────────────────────────
# Each tests/test_*.c is its own binary linked against the daemon's
# modules, so the real code is under test rather than a copy of it.

$(BUILDDIR)/test_%: tests/test_%.c $(LIBOBJS) | $(BUILDDIR)
	$(CC) $(ALLCFLAGS) -o $@ $< $(LIBOBJS) $(ALLLDFLAGS) $(LDLIBS)

test: $(TEST_BINS)
	@status=0; \
	for t in $(TEST_BINS); do \
	    echo "── $$t"; \
	    $$t || status=1; \
	done; \
	if [ $$status -eq 0 ]; then echo "  all tests passed"; \
	else echo "  TESTS FAILED"; fi; \
	exit $$status

# ── Install ──────────────────────────────────────────────────────────

install: $(TARGET)
	install -d $(DESTDIR)$(BINDIR) $(DESTDIR)$(SYSCONFDIR) $(DESTDIR)$(UNITDIR)
	install -m 755 $(TARGET) $(DESTDIR)$(BINDIR)/$(TARGET)
	install -m 644 knockd.service $(DESTDIR)$(UNITDIR)/knockd.service
	@# The config holds the knock sequence, so it is installed readable
	@# only by root, and an existing one is never overwritten.
	@if [ -f "$(DESTDIR)$(SYSCONFDIR)/knockd.conf" ]; then \
	    echo "  keeping existing $(DESTDIR)$(SYSCONFDIR)/knockd.conf"; \
	else \
	    install -m 600 knockd.conf.example $(DESTDIR)$(SYSCONFDIR)/knockd.conf; \
	    echo "  installed $(DESTDIR)$(SYSCONFDIR)/knockd.conf — edit the sequence before starting"; \
	fi
	@if [ -z "$(DESTDIR)" ] && command -v systemctl >/dev/null 2>&1; then \
	    systemctl daemon-reload; \
	fi
	@echo "  installed. Next: edit $(SYSCONFDIR)/knockd.conf, then"
	@echo "  sudo systemctl enable --now knockd"

uninstall:
	-systemctl disable --now knockd 2>/dev/null
	rm -f $(DESTDIR)$(BINDIR)/$(TARGET)
	rm -f $(DESTDIR)$(UNITDIR)/knockd.service
	@if [ -z "$(DESTDIR)" ] && command -v systemctl >/dev/null 2>&1; then \
	    systemctl daemon-reload; \
	fi
	@echo "  uninstalled. $(SYSCONFDIR)/knockd.conf was left in place."
	@echo "  The KNOCKD iptables chain is removed when the daemon stops;"
	@echo "  your own rules for port 22 are untouched."

clean:
	rm -rf $(BUILDDIR) $(TARGET)
	@echo "  cleaned"

-include $(DEPS)
