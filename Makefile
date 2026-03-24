# ──────────────────────────────────────────────────────
#  Lightweight VPN — Build System
#  Phases 1-4 complete
# ──────────────────────────────────────────────────────

CC      = gcc
CFLAGS  = -Wall -Wextra -O2 -D_GNU_SOURCE
LIBS    = -lssl -lcrypto -lpthread

all: vpnserver vpnclient hello_tun local_vpn

vpnserver: vpn_server_full.c
	$(CC) $(CFLAGS) $< -o $@ $(LIBS)
	@echo "✅  Built: vpnserver"

vpnclient: vpn_client_full.c
	$(CC) $(CFLAGS) $< -o $@ -lssl -lcrypto
	@echo "✅  Built: vpnclient"

# Phase 1 helpers (no OpenSSL needed)
hello_tun: hello_tun.c
	$(CC) $(CFLAGS) $< -o $@
	@echo "✅  Built: hello_tun"

local_vpn: local_vpn.c
	$(CC) $(CFLAGS) $< -o $@
	@echo "✅  Built: local_vpn"

clean:
	rm -f vpnserver vpnclient hello_tun local_vpn

.PHONY: all clean
