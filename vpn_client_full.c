// vpn_client_full.c
// Complete Lightweight VPN Client - Phase 2 + 3 + 4
// ✅ FULLY AUTOMATIC — no manual ip/route commands needed
//
// Compile: gcc vpn_client_full.c -o vpnclient -lssl -lcrypto
// Run:     sudo ./vpnclient <SERVER_IP>
//          sudo ./vpnclient <SERVER_IP> --full-tunnel   ← routes ALL internet via VPN

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
#define PORT               5555
#define BUFFER_SIZE        1500
#define ENC_BUF_SIZE       (BUFFER_SIZE + 256)
#define AES_KEY_SIZE       32
#define AES_IV_SIZE        12
#define AES_TAG_SIZE       16
#define DH_KEY_SIZE        512
#define KEEPALIVE_INTERVAL 30

#define MSG_HANDSHAKE_INIT 0x01
#define MSG_HANDSHAKE_RESP 0x02
#define MSG_IP_ASSIGN      0x03
#define MSG_DATA           0x04
#define MSG_KEEPALIVE      0x05
#define MSG_DISCONNECT     0x06

typedef struct {
    unsigned char  type;
    unsigned short length;
    unsigned char  data[];
} __attribute__((packed)) message_t;

// ─────────────────────────────────────────────
//  GLOBAL STATE
// ─────────────────────────────────────────────
static unsigned char    aes_key[AES_KEY_SIZE];
static int              key_established = 0;
static char             assigned_ip[64] = {0};
static char             tun_name[IFNAMSIZ] = "tun0";
static int              tun_fd  = -1;
static int              sock    = -1;
static volatile int     running = 1;
static struct sockaddr_in server_addr;
static time_t           last_keepalive = 0;
static int              full_tunnel    = 0;
static char             server_ip_str[64] = {0};

// ─────────────────────────────────────────────
//  TUN
// ─────────────────────────────────────────────
int tun_alloc(char *dev) {
    struct ifreq ifr;
    int fd = open("/dev/net/tun", O_RDWR);
    if (fd < 0) { perror("[ERROR] open /dev/net/tun"); exit(1); }
    memset(&ifr, 0, sizeof(ifr));
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
    strncpy(ifr.ifr_name, dev, IFNAMSIZ - 1);
    if (ioctl(fd, TUNSETIFF, (void *)&ifr) < 0) {
        perror("[ERROR] ioctl TUNSETIFF"); close(fd); exit(1);
    }
    strcpy(dev, ifr.ifr_name);
    return fd;
}

// ─────────────────────────────────────────────
//  AUTO NETWORK SETUP — called after IP assigned
// ─────────────────────────────────────────────
static char saved_gw[64]    = {0};
static char saved_dev[32]   = {0};

void auto_configure_tun(const char *dev, const char *ip) {
    char cmd[256];

    // Flush old addresses
    snprintf(cmd, sizeof(cmd), "ip addr flush dev %s 2>/dev/null", dev);
    system(cmd);

    // Assign IP
    snprintf(cmd, sizeof(cmd), "ip addr add %s/24 dev %s", ip, dev);
    if (system(cmd) != 0)
        fprintf(stderr, "[WARN] ip addr add failed (may already exist)\n");

    // Bring interface UP
    snprintf(cmd, sizeof(cmd), "ip link set %s up", dev);
    system(cmd);

    printf("[AUTO] ✅ tun0 configured: %s/24 — UP\n", ip);
}

void auto_setup_routing(const char *srv_ip, const char *dev) {
    char cmd[512];

    // ── Detect current default gateway & interface ──
    FILE *fp = popen("ip route show default 2>/dev/null", "r");
    char line[256] = {0};
    if (fp) { fgets(line, sizeof(line), fp); pclose(fp); }

    // Parse: "default via X.X.X.X dev ethX ..."
    char *via_pos = strstr(line, "via ");
    char *dev_pos = strstr(line, "dev ");
    if (via_pos) {
        sscanf(via_pos + 4, "%63s", saved_gw);
    }
    if (dev_pos) {
        sscanf(dev_pos + 4, "%31s", saved_dev);
    }

    if (strlen(saved_gw) == 0) {
        fprintf(stderr, "[WARN] Could not detect default gateway — skipping full-tunnel routing\n");
        return;
    }
    printf("[AUTO] Detected gateway: %s via %s\n", saved_gw, saved_dev);

    // ── Protect server IP (so VPN UDP doesn't loop) ──
    snprintf(cmd, sizeof(cmd),
             "ip route replace %s/32 via %s dev %s 2>/dev/null", srv_ip, saved_gw, saved_dev);
    system(cmd);
    printf("[AUTO] Protected server route: %s → %s\n", srv_ip, saved_gw);

    // ── Replace default route with VPN ──
    snprintf(cmd, sizeof(cmd), "ip route del default 2>/dev/null; true");
    system(cmd);

    // tun is point-to-point — no 'via', just 'dev'
    snprintf(cmd, sizeof(cmd), "ip route add default dev %s 2>/dev/null", dev);
    if (system(cmd) != 0) {
        fprintf(stderr, "[ERROR] Could not set default route via %s\n", dev);
        return;
    }
    printf("[AUTO] ✅ Default route → %s (VPN)\n", dev);

    // ── DNS ──
    system("cp /etc/resolv.conf /tmp/resolv.conf.vpn_bak 2>/dev/null");
    system("echo 'nameserver 8.8.8.8' > /etc/resolv.conf");
    printf("[AUTO] ✅ DNS set to 8.8.8.8\n");

    // ── Save gateway for restore ──
    FILE *f = fopen("/tmp/vpn_gw_bak", "w");
    if (f) { fprintf(f, "%s\n%s\n", saved_gw, saved_dev); fclose(f); }
}

void auto_restore_routing(const char *srv_ip, const char *dev) {
    char cmd[256];
    char gw[64] = {0}, iface[32] = {0};

    FILE *f = fopen("/tmp/vpn_gw_bak", "r");
    if (f) {
        fscanf(f, "%63s\n%31s\n", gw, iface);
        fclose(f);
    }

    // Remove VPN default route
    snprintf(cmd, sizeof(cmd), "ip route del default dev %s 2>/dev/null; true", dev);
    system(cmd);

    // Remove server protection route
    snprintf(cmd, sizeof(cmd), "ip route del %s/32 2>/dev/null; true", srv_ip);
    system(cmd);

    // Restore original default route
    if (strlen(gw) > 0) {
        snprintf(cmd, sizeof(cmd), "ip route add default via %s dev %s 2>/dev/null", gw, iface);
        system(cmd);
        printf("[AUTO] ✅ Restored original gateway: %s via %s\n", gw, iface);
    }

    // Restore DNS
    system("cp /tmp/resolv.conf.vpn_bak /etc/resolv.conf 2>/dev/null");
    printf("[AUTO] ✅ DNS restored\n");
}

// ─────────────────────────────────────────────
//  DH KEY EXCHANGE
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
    EVP_PKEY_CTX_free(ctx); EVP_PKEY_free(peer);
    return 0;
}

// ─────────────────────────────────────────────
//  AES-256-GCM
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
    EVP_CIPHER_CTX_free(ctx); return -1;
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
    EVP_CIPHER_CTX_free(ctx); return -1;
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
//  KEEPALIVE / DISCONNECT
// ─────────────────────────────────────────────
void send_keepalive(void) {
    unsigned char buf[sizeof(message_t)];
    message_t *msg = (message_t *)buf;
    msg->type = MSG_KEEPALIVE; msg->length = 0;
    sendto(sock, buf, sizeof(message_t), 0,
           (struct sockaddr *)&server_addr, sizeof(server_addr));
}

void send_disconnect(void) {
    unsigned char buf[sizeof(message_t)];
    message_t *msg = (message_t *)buf;
    msg->type = MSG_DISCONNECT; msg->length = 0;
    sendto(sock, buf, sizeof(message_t), 0,
           (struct sockaddr *)&server_addr, sizeof(server_addr));
    printf("[CLIENT] Sent graceful disconnect\n");
}

// ─────────────────────────────────────────────
//  SIGNAL
// ─────────────────────────────────────────────
void handle_signal(int sig) {
    (void)sig;
    printf("\n[CLIENT] Shutting down...\n");
    running = 0;
}

// ─────────────────────────────────────────────
//  HANDSHAKE — auto configures everything on success
// ─────────────────────────────────────────────
int perform_handshake(void) {
    EVP_PKEY *dh_key = generate_dh_key();
    if (!dh_key) { fprintf(stderr, "[HANDSHAKE] DH keygen failed\n"); return 0; }

    unsigned char *cli_pub = NULL;
    int pub_len = i2d_PUBKEY(dh_key, &cli_pub);
    if (pub_len <= 0) {
        fprintf(stderr, "[HANDSHAKE] Pubkey serialization failed\n");
        EVP_PKEY_free(dh_key); return 0;
    }

    unsigned char buf[ENC_BUF_SIZE];
    message_t *init_msg = (message_t *)buf;
    init_msg->type   = MSG_HANDSHAKE_INIT;
    init_msg->length = htons((unsigned short)pub_len);
    memcpy(init_msg->data, cli_pub, pub_len);
    sendto(sock, buf, sizeof(message_t) + pub_len, 0,
           (struct sockaddr *)&server_addr, sizeof(server_addr));
    OPENSSL_free(cli_pub);
    printf("[HANDSHAKE] Sent INIT...\n");

    // Wait for RESP (10s timeout)
    struct timeval tv = {10, 0};
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    int n = recvfrom(sock, buf, sizeof(buf), 0, NULL, NULL);
    if (n <= 0) {
        fprintf(stderr, "[HANDSHAKE] Timeout waiting for server response\n");
        EVP_PKEY_free(dh_key); return 0;
    }
    message_t *resp = (message_t *)buf;
    if (resp->type != MSG_HANDSHAKE_RESP) {
        fprintf(stderr, "[HANDSHAKE] Unexpected msg 0x%02x\n", resp->type);
        EVP_PKEY_free(dh_key); return 0;
    }

    size_t srv_pub_len = ntohs(resp->length);
    unsigned char shared_secret[DH_KEY_SIZE];
    size_t secret_len = sizeof(shared_secret);
    if (derive_shared_secret(dh_key, resp->data, srv_pub_len,
                             shared_secret, &secret_len) < 0) {
        fprintf(stderr, "[HANDSHAKE] Shared secret derivation failed\n");
        EVP_PKEY_free(dh_key); return 0;
    }
    derive_aes_key(shared_secret, secret_len, aes_key);
    key_established = 1;
    printf("[HANDSHAKE] ✅ AES-256-GCM key established\n");
    EVP_PKEY_free(dh_key);

    // Wait for IP assignment
    tv.tv_sec = 10; tv.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
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

    // Reset socket timeout
    tv.tv_sec = 0; tv.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    // ── AUTO CONFIGURE tun0 ──
    if (strlen(assigned_ip) > 0) {
        auto_configure_tun(tun_name, assigned_ip);

        // ── AUTO ROUTING (if --full-tunnel) ──
        if (full_tunnel) {
            printf("[AUTO] Setting up full-tunnel routing...\n");
            auto_setup_routing(server_ip_str, tun_name);
        }
    } else {
        fprintf(stderr, "[WARN] No IP assigned by server\n");
    }

    return 1;
}

// ─────────────────────────────────────────────
//  MAIN
// ─────────────────────────────────────────────
int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: sudo %s <SERVER_IP> [--full-tunnel]\n", argv[0]);
        fprintf(stderr, "  --full-tunnel : Route ALL internet traffic via VPN\n");
        return 1;
    }

    strncpy(server_ip_str, argv[1], sizeof(server_ip_str) - 1);
    full_tunnel = (argc >= 3 && strcmp(argv[2], "--full-tunnel") == 0);

    signal(SIGINT,  handle_signal);
    signal(SIGTERM, handle_signal);

    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    // Create TUN
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
    printf("║   Lightweight VPN Client  (AUTO Build)   ║\n");
    printf("║   Phase 2+3+4  |  AES-256-GCM  |  DH    ║\n");
    printf("╚══════════════════════════════════════════╝\n");
    printf("[CLIENT] Connecting to %s:%d\n", argv[1], PORT);
    if (full_tunnel)
        printf("[CLIENT] Mode: FULL TUNNEL — all traffic via VPN\n");
    else
        printf("[CLIENT] Mode: SPLIT TUNNEL — only VPN subnet routed\n");

    // Handshake + auto-configure
    if (!perform_handshake()) {
        fprintf(stderr, "[CLIENT] Handshake failed. Exiting.\n");
        close(tun_fd); close(sock); return 1;
    }

    printf("\n[CLIENT] ✅ VPN tunnel ACTIVE\n");
    if (full_tunnel) {
        printf("[CLIENT] 🌐 All internet traffic → VPN\n");
        printf("[CLIENT] Run: curl ifconfig.me  (should show server IP)\n");
    } else {
        printf("[CLIENT] Ping server: ping 10.8.0.1\n");
    }
    printf("[CLIENT] Press Ctrl+C to disconnect and restore routes\n\n");

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

        // Keepalive
        time_t now = time(NULL);
        if (now - last_keepalive >= KEEPALIVE_INTERVAL) {
            send_keepalive();
            last_keepalive = now;
        }

        // TUN → UDP (encrypt and send)
        if (FD_ISSET(tun_fd, &rfds)) {
            int n = read(tun_fd, plain, sizeof(plain));
            if (n > 0 && key_established) {
                unsigned char iv[AES_IV_SIZE], tag[AES_TAG_SIZE];
                if (RAND_bytes(iv, AES_IV_SIZE) != 1) continue;
                int clen = aes_gcm_encrypt(aes_key, plain, n, iv, cipher, tag);
                if (clen > 0) {
                    message_t *dmsg = (message_t *)buf;
                    int plen = AES_IV_SIZE + AES_TAG_SIZE + clen;
                    dmsg->type   = MSG_DATA;
                    dmsg->length = htons((unsigned short)plen);
                    memcpy(dmsg->data,                              iv,     AES_IV_SIZE);
                    memcpy(dmsg->data + AES_IV_SIZE,                tag,    AES_TAG_SIZE);
                    memcpy(dmsg->data + AES_IV_SIZE + AES_TAG_SIZE, cipher, clen);
                    sendto(sock, buf, sizeof(message_t) + plen, 0,
                           (struct sockaddr *)&server_addr, sizeof(server_addr));
                }
            }
        }

        // UDP → TUN (decrypt and write)
        if (FD_ISSET(sock, &rfds)) {
            int n = recvfrom(sock, buf, sizeof(buf), 0, NULL, NULL);
            if (n < (int)sizeof(message_t)) continue;
            message_t *msg = (message_t *)buf;
            unsigned short plen = ntohs(msg->length);

            if (msg->type == MSG_DATA && key_established) {
                if (plen < AES_IV_SIZE + AES_TAG_SIZE) continue;
                unsigned char iv[AES_IV_SIZE], tag[AES_TAG_SIZE];
                memcpy(iv,  msg->data,              AES_IV_SIZE);
                memcpy(tag, msg->data + AES_IV_SIZE, AES_TAG_SIZE);
                int clen = plen - AES_IV_SIZE - AES_TAG_SIZE;
                if (clen <= 0) continue;
                int dlen = aes_gcm_decrypt(aes_key,
                                           msg->data + AES_IV_SIZE + AES_TAG_SIZE,
                                           clen, tag, iv, plain);
                if (dlen > 0)
                    write(tun_fd, plain, dlen);
            }
        }
    }

    // ── Graceful shutdown ──
    send_disconnect();
    if (full_tunnel)
        auto_restore_routing(server_ip_str, tun_name);

    close(tun_fd);
    close(sock);
    EVP_cleanup();
    CRYPTO_cleanup_all_ex_data();
    ERR_free_strings();
    printf("[CLIENT] 👋 Goodbye.\n");
    return 0;
}