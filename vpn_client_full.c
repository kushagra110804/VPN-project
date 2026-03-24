// vpn_client_full.c
// Complete Lightweight VPN Client - Phase 2 + 3 + 4
//
// Compile: gcc vpn_client_full.c -o vpnclient -lssl -lcrypto
// Run as root: sudo ./vpnclient <SERVER_IP>

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <signal.h>
#include <sys/ioctl.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <linux/if_tun.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <time.h>

// ─────────────────────────────────────────────
//  CONFIGURATION
// ─────────────────────────────────────────────
#define PORT              5555
#define BUFFER_SIZE       1500
#define ENC_BUF_SIZE      (BUFFER_SIZE + 256)
#define AES_KEY_SIZE      32
#define AES_IV_SIZE       12
#define AES_TAG_SIZE      16
#define DH_KEY_SIZE       512
#define KEEPALIVE_INTERVAL 30   // seconds

// Protocol message types
#define MSG_HANDSHAKE_INIT 0x01
#define MSG_HANDSHAKE_RESP 0x02
#define MSG_IP_ASSIGN      0x03
#define MSG_DATA           0x04
#define MSG_KEEPALIVE      0x05
#define MSG_DISCONNECT     0x06

typedef struct {
    unsigned char type;
    unsigned short length;
    unsigned char data[];
} __attribute__((packed)) message_t;

// ─────────────────────────────────────────────
//  STATE
// ─────────────────────────────────────────────
static unsigned char aes_key[AES_KEY_SIZE];
static int  key_established = 0;
static char assigned_ip[64] = {0};
static int  tun_fd = -1;
static int  sock   = -1;
static volatile int running = 1;
static struct sockaddr_in server_addr;
static time_t last_keepalive = 0;

// ─────────────────────────────────────────────
//  MODULE: TUN
// ─────────────────────────────────────────────
int tun_alloc(char *dev) {
    struct ifreq ifr;
    int fd = open("/dev/net/tun", O_RDWR);
    if (fd < 0) { perror("open /dev/net/tun"); exit(1); }
    memset(&ifr, 0, sizeof(ifr));
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
    strncpy(ifr.ifr_name, dev, IFNAMSIZ - 1);
    ifr.ifr_name[IFNAMSIZ - 1] = 0;
    if (ioctl(fd, TUNSETIFF, (void *)&ifr) < 0) { perror("ioctl TUNSETIFF"); close(fd); exit(1); }
    strcpy(dev, ifr.ifr_name);
    return fd;
}

void configure_tun_client(const char *dev, const char *ip) {
    char cmd[256];
    // Remove any existing address first
    snprintf(cmd, sizeof(cmd), "ip addr flush dev %s 2>/dev/null", dev);
    system(cmd);
    snprintf(cmd, sizeof(cmd), "ip addr add %s/24 dev %s", ip, dev);
    system(cmd);
    snprintf(cmd, sizeof(cmd), "ip link set %s up", dev);
    system(cmd);
    printf("[TUN] Interface %s configured: %s/24\n", dev, ip);
}

// ─────────────────────────────────────────────
//  MODULE: PHASE 4 — INTERNET ROUTING (client side)
// ─────────────────────────────────────────────
// Call after TUN is configured. Routes ALL traffic through VPN.
// Saves original default gateway before overriding.
void setup_client_routing(const char *server_ip, const char *tun_dev) {
    char cmd[512];

    // Find current default gateway
    FILE *fp = popen("ip route show default | awk '{print $3}' | head -1", "r");
    char gw[64] = {0};
    if (fp) { fgets(gw, sizeof(gw), fp); pclose(fp); }
    // Strip newline
    gw[strcspn(gw, "\n")] = 0;

    if (strlen(gw) == 0) {
        fprintf(stderr, "[ROUTE] Could not find default gateway, skipping routing setup\n");
        return;
    }
    printf("[ROUTE] Detected default gateway: %s\n", gw);

    // Keep server traffic going through real interface
    snprintf(cmd, sizeof(cmd), "ip route add %s via %s 2>/dev/null || true", server_ip, gw);
    system(cmd);

    // Route all other traffic through VPN TUN
    snprintf(cmd, sizeof(cmd), "ip route del default 2>/dev/null || true");
    system(cmd);
    snprintf(cmd, sizeof(cmd), "ip route add default dev %s", tun_dev);
    system(cmd);

    // DNS: use a public DNS over the VPN (Phase 4 DNS forwarding)
    printf("[ROUTE] Adding DNS route through VPN...\n");
    system("echo 'nameserver 8.8.8.8' > /tmp/vpn_resolv.conf");
    system("cp /etc/resolv.conf /tmp/resolv.conf.bak 2>/dev/null");
    system("cp /tmp/vpn_resolv.conf /etc/resolv.conf");

    printf("[ROUTE] ✅ All internet traffic now routed through VPN\n");
    printf("[ROUTE] Original gateway (%s) saved. Run --restore-routes to undo.\n", gw);

    // Save gateway for cleanup
    FILE *f = fopen("/tmp/vpn_orig_gw", "w");
    if (f) { fprintf(f, "%s\n", gw); fclose(f); }
}

void restore_client_routing(const char *server_ip, const char *tun_dev) {
    char gw[64] = {0};
    FILE *f = fopen("/tmp/vpn_orig_gw", "r");
    if (f) { fgets(gw, sizeof(gw), f); fclose(f); gw[strcspn(gw, "\n")] = 0; }

    char cmd[256];
    if (strlen(gw) > 0) {
        printf("[ROUTE] Restoring default gateway via %s\n", gw);
        system("ip route del default 2>/dev/null || true");
        snprintf(cmd, sizeof(cmd), "ip route add default via %s", gw);
        system(cmd);
        // Remove server-specific route
        snprintf(cmd, sizeof(cmd), "ip route del %s via %s 2>/dev/null || true", server_ip, gw);
        system(cmd);
    }
    // Restore DNS
    system("cp /tmp/resolv.conf.bak /etc/resolv.conf 2>/dev/null || true");
    (void)tun_dev;
    printf("[ROUTE] Routes restored.\n");
}

// ─────────────────────────────────────────────
//  MODULE: DH KEY EXCHANGE
// ─────────────────────────────────────────────
EVP_PKEY *generate_dh_key(void) {
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_DH, NULL);
    if (!pctx) return NULL;
    if (EVP_PKEY_paramgen_init(pctx) <= 0) { EVP_PKEY_CTX_free(pctx); return NULL; }
    if (EVP_PKEY_CTX_set_dh_nid(pctx, NID_ffdhe2048) <= 0) { EVP_PKEY_CTX_free(pctx); return NULL; }
    EVP_PKEY *params = NULL;
    if (EVP_PKEY_paramgen(pctx, &params) <= 0) { EVP_PKEY_CTX_free(pctx); return NULL; }
    EVP_PKEY_CTX_free(pctx);
    EVP_PKEY_CTX *kctx = EVP_PKEY_CTX_new(params, NULL);
    EVP_PKEY_free(params);
    if (!kctx) return NULL;
    if (EVP_PKEY_keygen_init(kctx) <= 0) { EVP_PKEY_CTX_free(kctx); return NULL; }
    EVP_PKEY *key = NULL;
    EVP_PKEY_keygen(kctx, &key);
    EVP_PKEY_CTX_free(kctx);
    return key;
}

int derive_shared_secret(EVP_PKEY *privkey,
                         const unsigned char *peer_pub, size_t peer_pub_len,
                         unsigned char *secret, size_t *secret_len) {
    EVP_PKEY *peer = NULL;
    const unsigned char *p = peer_pub;
    if (!d2i_PUBKEY(&peer, &p, (long)peer_pub_len)) return -1;
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(privkey, NULL);
    if (!ctx) { EVP_PKEY_free(peer); return -1; }
    if (EVP_PKEY_derive_init(ctx) <= 0 ||
        EVP_PKEY_derive_set_peer(ctx, peer) <= 0 ||
        EVP_PKEY_derive(ctx, NULL, secret_len) <= 0 ||
        EVP_PKEY_derive(ctx, secret, secret_len) <= 0) {
        EVP_PKEY_CTX_free(ctx); EVP_PKEY_free(peer); return -1;
    }
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(peer);
    return 0;
}

// ─────────────────────────────────────────────
//  MODULE: AES-256-GCM CRYPTO
// ─────────────────────────────────────────────
int aes_gcm_encrypt(const unsigned char *key,
                    const unsigned char *plain, int plain_len,
                    unsigned char *iv,
                    unsigned char *cipher, unsigned char *tag) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;
    int len = 0, out_len = 0;
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) <= 0) goto err;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, AES_IV_SIZE, NULL) <= 0) goto err;
    if (EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv) <= 0) goto err;
    if (EVP_EncryptUpdate(ctx, cipher, &len, plain, plain_len) <= 0) goto err;
    out_len = len;
    if (EVP_EncryptFinal_ex(ctx, cipher + len, &len) <= 0) goto err;
    out_len += len;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, AES_TAG_SIZE, tag) <= 0) goto err;
    EVP_CIPHER_CTX_free(ctx);
    return out_len;
err:
    EVP_CIPHER_CTX_free(ctx);
    return -1;
}

int aes_gcm_decrypt(const unsigned char *key,
                    const unsigned char *cipher, int cipher_len,
                    const unsigned char *tag, const unsigned char *iv,
                    unsigned char *plain) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;
    int len = 0, out_len = 0;
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) <= 0) goto err;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, AES_IV_SIZE, NULL) <= 0) goto err;
    if (EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv) <= 0) goto err;
    if (EVP_DecryptUpdate(ctx, plain, &len, cipher, cipher_len) <= 0) goto err;
    out_len = len;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, AES_TAG_SIZE, (void *)tag) <= 0) goto err;
    if (EVP_DecryptFinal_ex(ctx, plain + len, &len) <= 0) { EVP_CIPHER_CTX_free(ctx); return -1; }
    out_len += len;
    EVP_CIPHER_CTX_free(ctx);
    return out_len;
err:
    EVP_CIPHER_CTX_free(ctx);
    return -1;
}

void derive_aes_key(const unsigned char *secret, size_t len, unsigned char *out) {
    EVP_MD_CTX *md = EVP_MD_CTX_new();
    unsigned int out_len = 0;
    EVP_DigestInit_ex(md, EVP_sha256(), NULL);
    EVP_DigestUpdate(md, secret, len);
    EVP_DigestFinal_ex(md, out, &out_len);
    EVP_MD_CTX_free(md);
}

// ─────────────────────────────────────────────
//  SIGNAL HANDLER
// ─────────────────────────────────────────────
void handle_signal(int sig) {
    (void)sig;
    printf("\n[CLIENT] Shutting down...\n");
    running = 0;
}

// ─────────────────────────────────────────────
//  HANDSHAKE
// ─────────────────────────────────────────────
EVP_PKEY *perform_handshake(void) {
    EVP_PKEY *dh_key = generate_dh_key();
    if (!dh_key) { fprintf(stderr, "[HANDSHAKE] DH key gen failed\n"); return NULL; }

    unsigned char *cli_pub = NULL;
    int pub_len = i2d_PUBKEY(dh_key, &cli_pub);
    if (pub_len <= 0) {
        fprintf(stderr, "[HANDSHAKE] Failed to serialize pubkey\n");
        EVP_PKEY_free(dh_key);
        return NULL;
    }

    unsigned char buf[ENC_BUF_SIZE];
    message_t *init_msg = (message_t *)buf;
    init_msg->type   = MSG_HANDSHAKE_INIT;
    init_msg->length = htons((unsigned short)pub_len);
    memcpy(init_msg->data, cli_pub, pub_len);
    sendto(sock, buf, sizeof(message_t) + pub_len, 0,
           (struct sockaddr *)&server_addr, sizeof(server_addr));
    OPENSSL_free(cli_pub);
    printf("[HANDSHAKE] Sent INIT to server\n");

    // Wait for RESP
    struct timeval tv = {10, 0};
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    int n = recvfrom(sock, buf, sizeof(buf), 0, NULL, NULL);
    if (n <= 0) {
        fprintf(stderr, "[HANDSHAKE] Timed out waiting for RESP\n");
        EVP_PKEY_free(dh_key);
        return NULL;
    }
    message_t *resp = (message_t *)buf;
    if (resp->type != MSG_HANDSHAKE_RESP) {
        fprintf(stderr, "[HANDSHAKE] Unexpected msg type 0x%02x\n", resp->type);
        EVP_PKEY_free(dh_key);
        return NULL;
    }
    size_t srv_pub_len = ntohs(resp->length);
    if (srv_pub_len > (size_t)(n - sizeof(message_t))) {
        fprintf(stderr, "[HANDSHAKE] Truncated server pubkey\n");
        EVP_PKEY_free(dh_key);
        return NULL;
    }

    unsigned char shared_secret[DH_KEY_SIZE];
    size_t secret_len = sizeof(shared_secret);
    if (derive_shared_secret(dh_key, resp->data, srv_pub_len,
                             shared_secret, &secret_len) < 0) {
        fprintf(stderr, "[HANDSHAKE] Shared secret derivation failed\n");
        EVP_PKEY_free(dh_key);
        return NULL;
    }
    derive_aes_key(shared_secret, secret_len, aes_key);
    key_established = 1;
    printf("[HANDSHAKE] ✅ AES-256-GCM key established\n");

    // Wait for IP assignment
    n = recvfrom(sock, buf, sizeof(buf), 0, NULL, NULL);
    if (n > 0) {
        message_t *ip_msg = (message_t *)buf;
        if (ip_msg->type == MSG_IP_ASSIGN) {
            int ip_len = ntohs(ip_msg->length);
            if (ip_len >= (int)sizeof(assigned_ip)) ip_len = sizeof(assigned_ip) - 1;
            memcpy(assigned_ip, ip_msg->data, ip_len);
            assigned_ip[ip_len] = '\0';
            printf("[IP-POOL] ✅ Assigned virtual IP: %s\n", assigned_ip);
        }
    }

    // Reset socket timeout (non-blocking select loop)
    tv.tv_sec = 0; tv.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    EVP_PKEY_free(dh_key);
    return (EVP_PKEY *)1;   // success sentinel
}

// ─────────────────────────────────────────────
//  SEND KEEPALIVE
// ─────────────────────────────────────────────
void send_keepalive(void) {
    unsigned char buf[sizeof(message_t)];
    message_t *msg = (message_t *)buf;
    msg->type   = MSG_KEEPALIVE;
    msg->length = 0;
    sendto(sock, buf, sizeof(message_t), 0,
           (struct sockaddr *)&server_addr, sizeof(server_addr));
}

// ─────────────────────────────────────────────
//  SEND DISCONNECT
// ─────────────────────────────────────────────
void send_disconnect(void) {
    unsigned char buf[sizeof(message_t)];
    message_t *msg = (message_t *)buf;
    msg->type   = MSG_DISCONNECT;
    msg->length = 0;
    sendto(sock, buf, sizeof(message_t), 0,
           (struct sockaddr *)&server_addr, sizeof(server_addr));
    printf("[CLIENT] Sent graceful disconnect to server\n");
}

// ─────────────────────────────────────────────
//  MAIN
// ─────────────────────────────────────────────
int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <server_ip> [--full-tunnel]\n", argv[0]);
        fprintf(stderr, "  --full-tunnel : Route ALL internet traffic through VPN (Phase 4)\n");
        return 1;
    }

    int full_tunnel = (argc >= 3 && strcmp(argv[2], "--full-tunnel") == 0);

    signal(SIGINT,  handle_signal);
    signal(SIGTERM, handle_signal);

    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    // Create TUN
    char tun_name[IFNAMSIZ] = "tun0";
    tun_fd = tun_alloc(tun_name);
    printf("[TUN] Created: %s\n", tun_name);

    // UDP socket
    sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) { perror("socket"); exit(1); }

    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port   = htons(PORT);
    if (inet_pton(AF_INET, argv[1], &server_addr.sin_addr) <= 0) {
        perror("inet_pton"); exit(1);
    }

    printf("╔══════════════════════════════════════════╗\n");
    printf("║   Lightweight VPN Client  (Full Build)   ║\n");
    printf("║   Phase 2+3+4  |  AES-256-GCM  |  DH    ║\n");
    printf("╚══════════════════════════════════════════╝\n");
    printf("[CLIENT] Connecting to %s:%d\n", argv[1], PORT);

    // Perform DH handshake
    if (!perform_handshake()) {
        fprintf(stderr, "[CLIENT] Handshake failed. Exiting.\n");
        close(tun_fd); close(sock);
        return 1;
    }

    // Configure TUN with assigned IP
    if (strlen(assigned_ip) > 0) {
        configure_tun_client(tun_name, assigned_ip);
    }

    // Phase 4: full-tunnel internet routing
    if (full_tunnel && strlen(assigned_ip) > 0) {
        printf("[ROUTE] Setting up full-tunnel internet routing...\n");
        setup_client_routing(argv[1], tun_name);
    }

    printf("[CLIENT] ✅ VPN tunnel active. Press Ctrl+C to disconnect.\n\n");
    last_keepalive = time(NULL);

    unsigned char buf[ENC_BUF_SIZE];
    unsigned char plain[BUFFER_SIZE];
    unsigned char cipher[BUFFER_SIZE + 64];

    while (running) {
        fd_set rfds;
        FD_ZERO(&rfds);
        FD_SET(tun_fd, &rfds);
        FD_SET(sock,   &rfds);
        int maxfd = tun_fd > sock ? tun_fd : sock;

        struct timeval tv = {1, 0};
        int ret = select(maxfd + 1, &rfds, NULL, NULL, &tv);
        if (ret < 0) { if (errno == EINTR) continue; perror("select"); continue; }

        // ── Keepalive ──
        time_t now = time(NULL);
        if (now - last_keepalive >= KEEPALIVE_INTERVAL) {
            send_keepalive();
            last_keepalive = now;
        }

        // ── TUN → UDP ──
        if (FD_ISSET(tun_fd, &rfds)) {
            int n = read(tun_fd, plain, sizeof(plain));
            if (n > 0 && key_established) {
                unsigned char iv[AES_IV_SIZE], tag[AES_TAG_SIZE];
                if (RAND_bytes(iv, AES_IV_SIZE) != 1) continue;
                int clen = aes_gcm_encrypt(aes_key, plain, n, iv, cipher, tag);
                if (clen > 0) {
                    message_t *dmsg = (message_t *)buf;
                    int payload_len = AES_IV_SIZE + AES_TAG_SIZE + clen;
                    dmsg->type   = MSG_DATA;
                    dmsg->length = htons((unsigned short)payload_len);
                    memcpy(dmsg->data,                              iv,     AES_IV_SIZE);
                    memcpy(dmsg->data + AES_IV_SIZE,                tag,    AES_TAG_SIZE);
                    memcpy(dmsg->data + AES_IV_SIZE + AES_TAG_SIZE, cipher, clen);
                    sendto(sock, buf, sizeof(message_t) + payload_len, 0,
                           (struct sockaddr *)&server_addr, sizeof(server_addr));
                    printf("[TUN→UDP] %d bytes encrypted → server\n", n);
                }
            }
        }

        // ── UDP → TUN ──
        if (FD_ISSET(sock, &rfds)) {
            int n = recvfrom(sock, buf, sizeof(buf), 0, NULL, NULL);
            if (n < (int)sizeof(message_t)) continue;
            message_t *msg = (message_t *)buf;
            unsigned short payload_len = ntohs(msg->length);

            if (msg->type == MSG_DATA && key_established) {
                if (payload_len < AES_IV_SIZE + AES_TAG_SIZE) continue;
                unsigned char iv[AES_IV_SIZE], tag[AES_TAG_SIZE];
                memcpy(iv,  msg->data,               AES_IV_SIZE);
                memcpy(tag, msg->data + AES_IV_SIZE,  AES_TAG_SIZE);
                int clen = payload_len - AES_IV_SIZE - AES_TAG_SIZE;
                if (clen <= 0) continue;
                int plen = aes_gcm_decrypt(aes_key,
                                           msg->data + AES_IV_SIZE + AES_TAG_SIZE,
                                           clen, tag, iv, plain);
                if (plen > 0) {
                    write(tun_fd, plain, plen);
                    printf("[UDP→TUN] %d bytes decrypted ← server\n", plen);
                } else {
                    fprintf(stderr, "[CRYPTO] Decrypt failed\n");
                }
            }
        }
    }

    // Graceful shutdown
    send_disconnect();

    if (full_tunnel) {
        restore_client_routing(argv[1], tun_name);
    }

    close(tun_fd);
    close(sock);
    EVP_cleanup();
    CRYPTO_cleanup_all_ex_data();
    ERR_free_strings();
    printf("[CLIENT] Goodbye.\n");
    return 0;
}
