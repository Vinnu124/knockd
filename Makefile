# ──────────────────────────────────────────────────────────────────────
# Makefile — Port Knocking Daemon (knockd)
#
# Build:   make
# Clean:   make clean
# Debug:   make debug
# ──────────────────────────────────────────────────────────────────────

CC      = gcc
CFLAGS  = -Wall -Wextra -Werror -O2 -pthread -fopenmp -std=c11 -I include -D_GNU_SOURCE
LDFLAGS = -pthread -fopenmp

# Source files
SRC     = src/main.c src/sniffer.c src/knocker.c src/firewall.c src/logger.c src/packet_queue.c src/config.c

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
debug: CFLAGS = -Wall -Wextra -g -O0 -pthread -fopenmp -std=c11 -I include -D_GNU_SOURCE -DDEBUG
debug: $(TARGET)
	@echo "  (debug build)"

clean:
	rm -f $(TARGET)
	@echo "  ✓ Cleaned"

install: $(TARGET)
	@echo "  Installing to system..."
	install -d /usr/local/bin /etc /etc/systemd/system
	install -m 755 $(TARGET) /usr/local/bin/$(TARGET)
	install -m 644 knockd.conf.example /etc/knockd.conf
	install -m 644 knockd.service /etc/systemd/system/
	systemctl daemon-reload
	@echo "  ✓ Installed successfully"
	@echo "  Start service with: sudo systemctl start knockd"

uninstall:
	@echo "  Uninstalling..."
	systemctl stop knockd || true
	systemctl disable knockd || true
	rm -f /usr/local/bin/$(TARGET)
	rm -f /etc/knockd.conf
	rm -f /etc/systemd/system/knockd.service
	systemctl daemon-reload
	@echo "  ✓ Uninstalled successfully"
