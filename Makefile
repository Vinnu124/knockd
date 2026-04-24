# ──────────────────────────────────────────────────────────────────────
# Makefile — Port Knocking Daemon (knockd)
#
# Build:   make
# Clean:   make clean
# Debug:   make debug
# ──────────────────────────────────────────────────────────────────────

CC      = gcc
CFLAGS  = -Wall -Wextra -Werror -O2 -pthread -std=c11 -I include -D_GNU_SOURCE
LDFLAGS = -pthread

# Source files
SRC     = src/main.c src/sniffer.c src/knocker.c src/firewall.c src/logger.c

# Output binary
TARGET  = knockd

# ── Targets ──────────────────────────────────────────────────────────

.PHONY: all clean debug

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^
	@echo ""
	@echo "  ✓ Built $(TARGET) successfully"
	@echo "  Run with: sudo ./$(TARGET)"
	@echo ""

# Debug build: no optimization, debug symbols, extra warnings
debug: CFLAGS = -Wall -Wextra -g -O0 -pthread -std=c11 -DDEBUG
debug: $(TARGET)
	@echo "  (debug build)"

clean:
	rm -f $(TARGET)
	@echo "  ✓ Cleaned"
