// vpn_server_full.c
// Complete Lightweight VPN Server - Phase 2 + 3 + 4
// Features: IP Allocator, Multi-client, NAT/Internet routing
//
// Compile: gcc vpn_server_full.c -o vpnserver -lssl -lcrypto -lpthread
// Run as root: sudo ./vpnserver
// Setup NAT (run once): sudo ./vpnserver --setup-nat eth0
//
// Post-start TUN config:
//   sudo ip addr add 10.8.0.1/24 dev tun0
//   sudo ip link set tun0 up

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <signal.h>
#include <pthread.h>
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

#define MAX_CLIENTS       32          // Phase 3: multi-client
#define SESSION_TIMEOUT   300         // seconds of inactivity before cleanup

#define VPN_SUBNET        "10.8.0"    // Virtual IP pool: 10.8.0.2 – 10.8.0.254
#define VPN_SERVER_IP     "10.8.0.1"
#define IP_POOL_START     2
#define IP_POOL_END       254

// Protocol message types
#define MSG_HANDSHAKE_INIT 0x01
#define MSG_HANDSHAKE_RESP 0x02
#define MSG_IP_ASSIGN      0x03
#define MSG_DATA           0x04
#define MSG_KEEPALIVE      0x05
#define MSG_DISCONNECT     0x06

// ─────────────────────────────────────────────
//  DATA STRUCTURES
// ─────────────────────────────────────────────
typedef struct {
    unsigned char type;
    unsigned short length;   // network byte order
    unsigned char data[];
} __attribute__((packed)) message_t;

typedef struct {
    int            active;
    struct sockaddr_in addr;
    socklen_t      addr_len;
    unsigned char  aes_key[AES_KEY_SIZE];
    char           virtual_ip[32];    // e.g. "10.8.0.3"
    time_t         last_seen;
    EVP_PKEY      *dh_key;            // freed after handshake
    int            handshake_done;
} client_session_t;

// Global state
static client_session_t clients[MAX_CLIENTS];
static pthread_mutex_t  clients_lock = PTHREAD_MUTEX_INITIALIZER;
static int ip_pool_used[IP_POOL_END + 1];  // 1 = in use
static int tun_fd_global = -1;
static int sock_global   = -1;
static volatile int running = 1;

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
    printf("[TUN] Created interface: %s\n", dev);
    return fd;
}

// ─────────────────────────────────────────────
//  MODULE: IP ALLOCATOR  (Phase 2 completion)
// ─────────────────────────────────────────────
// Allocate next free IP from pool; returns 1 on success
int ip_allocate(char *out_ip, size_t out_len) {
    pthread_mutex_lock(&clients_lock);
    for (int i = IP_POOL_START; i <= IP_POOL_END; i++) {
        if (!ip_pool_used[i]) {
            ip_pool_used[i] = 1;
            snprintf(out_ip, out_len, "%s.%d", VPN_SUBNET, i);
            pthread_mutex_unlock(&clients_lock);
            return 1;
        }
    }
    pthread_mutex_unlock(&clients_lock);
    return 0;   // pool exhausted
}

void ip_release(const char *ip) {
    // Parse last octet
    const char *last_dot = strrchr(ip, '.');
    if (!last_dot) return;
    int octet = atoi(last_dot + 1);
    if (octet >= IP_POOL_START && octet <= IP_POOL_END) {
        pthread_mutex_lock(&clients_lock);
        ip_pool_used[octet] = 0;
        pthread_mutex_unlock(&clients_lock);
        printf("[IP-POOL] Released %s\n", ip);
    }
}

// ─────────────────────────────────────────────
//  MODULE: SESSION MANAGER  (Phase 3)
// ─────────────────────────────────────────────
// Find existing session by client address; returns index or -1
int session_find(const struct sockaddr_in *addr) {
    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (clients[i].active &&
            clients[i].addr.sin_addr.s_addr == addr->sin_addr.s_addr &&
            clients[i].addr.sin_port        == addr->sin_port) {
            return i;
        }
    }
    return -1;
}

// Allocate new session slot; returns index or -1
int session_new(const struct sockaddr_in *addr, socklen_t addr_len) {
    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (!clients[i].active) {
            memset(&clients[i], 0, sizeof(clients[i]));
            clients[i].active   = 1;
            clients[i].addr     = *addr;
            clients[i].addr_len = addr_len;
            clients[i].last_seen = time(NULL);
            return i;
        }
    }
    return -1;
}

void session_free(int idx) {
    if (idx < 0 || idx >= MAX_CLIENTS) return;
    if (clients[idx].dh_key) {
        EVP_PKEY_free(clients[idx].dh_key);
        clients[idx].dh_key = NULL;
    }
    if (strlen(clients[idx].virtual_ip) > 0)
        ip_release(clients[idx].virtual_ip);
    printf("[SESSION] Freed session %d (was %s)\n", idx, clients[idx].virtual_ip);
    memset(&clients[idx], 0, sizeof(clients[idx]));
}

// Background thread: reap timed-out sessions
void *session_reaper(void *arg) {
    (void)arg;
    while (running) {
        sleep(30);
        time_t now = time(NULL);
        pthread_mutex_lock(&clients_lock);
        for (int i = 0; i < MAX_CLIENTS; i++) {
            if (clients[i].active && (now - clients[i].last_seen) > SESSION_TIMEOUT) {
                printf("[REAPER] Session %d (%s) timed out\n", i, clients[i].virtual_ip);
                session_free(i);
            }
        }
        pthread_mutex_unlock(&clients_lock);
    }
    return NULL;
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
//  MODULE: NAT / INTERNET ROUTING  (Phase 4)
// ─────────────────────────────────────────────
// Call once at startup with the real outbound interface (e.g. "eth0")
void setup_nat(const char *wan_iface, const char *tun_iface) {
    char cmd[512];

    printf("[NAT] Enabling IP forwarding...\n");
    system("echo 1 > /proc/sys/net/ipv4/ip_forward");
    // Persist across reboots
    system("sysctl -w net.ipv4.ip_forward=1 > /dev/null 2>&1");

    printf("[NAT] Adding iptables MASQUERADE rule on %s...\n", wan_iface);
    snprintf(cmd, sizeof(cmd),
             "iptables -t nat -A POSTROUTING -s 10.8.0.0/24 -o %s -j MASQUERADE",
             wan_iface);
    system(cmd);

    printf("[NAT] Allowing forwarded traffic...\n");
    snprintf(cmd, sizeof(cmd),
             "iptables -A FORWARD -i %s -o %s -j ACCEPT", tun_iface, wan_iface);
    system(cmd);
    snprintf(cmd, sizeof(cmd),
             "iptables -A FORWARD -i %s -o %s -m state --state RELATED,ESTABLISHED -j ACCEPT",
             wan_iface, tun_iface);
    system(cmd);

    printf("[NAT] ✅ NAT configured: VPN clients can now reach the internet via %s\n", wan_iface);
}

// Configure the TUN interface IP programmatically
void configure_tun(const char *dev) {
    char cmd[256];
    snprintf(cmd, sizeof(cmd), "ip addr add %s/24 dev %s 2>/dev/null || true", VPN_SERVER_IP, dev);
    system(cmd);
    snprintf(cmd, sizeof(cmd), "ip link set %s up", dev);
    system(cmd);
    printf("[TUN] Interface %s configured with %s/24\n", dev, VPN_SERVER_IP);
}

// ─────────────────────────────────────────────
//  HANDSHAKE HANDLER
// ─────────────────────────────────────────────
void handle_handshake(int sock, int idx,
                      unsigned char *buf, int n,
                      const struct sockaddr_in *cli_addr, socklen_t cli_len) {
    message_t *msg = (message_t *)buf;
    unsigned short payload_len = ntohs(msg->length);

    if ((size_t)(n - sizeof(message_t)) < payload_len) {
        fprintf(stderr, "[HANDSHAKE] Truncated handshake from client %d\n", idx);
        return;
    }

    // Generate server DH key
    clients[idx].dh_key = generate_dh_key();
    if (!clients[idx].dh_key) {
        fprintf(stderr, "[HANDSHAKE] DH key generation failed\n");
        return;
    }

    // Derive shared secret using client's pubkey
    unsigned char shared_secret[DH_KEY_SIZE];
    size_t secret_len = sizeof(shared_secret);
    if (derive_shared_secret(clients[idx].dh_key,
                             msg->data, payload_len,
                             shared_secret, &secret_len) < 0) {
        fprintf(stderr, "[HANDSHAKE] Failed to derive shared secret\n");
        return;
    }
    derive_aes_key(shared_secret, secret_len, clients[idx].aes_key);
    printf("[HANDSHAKE] Session %d: AES-256-GCM key derived\n", idx);

    // Send server pubkey
    unsigned char *srv_pub = NULL;
    int srv_pub_len = i2d_PUBKEY(clients[idx].dh_key, &srv_pub);
    if (srv_pub_len <= 0 || srv_pub_len > (int)(ENC_BUF_SIZE - sizeof(message_t))) {
        fprintf(stderr, "[HANDSHAKE] Server pubkey serialization failed\n");
        OPENSSL_free(srv_pub);
        return;
    }
    unsigned char resp_buf[ENC_BUF_SIZE];
    message_t *resp = (message_t *)resp_buf;
    resp->type   = MSG_HANDSHAKE_RESP;
    resp->length = htons(srv_pub_len);
    memcpy(resp->data, srv_pub, srv_pub_len);
    sendto(sock, resp_buf, sizeof(message_t) + srv_pub_len, 0,
           (struct sockaddr *)cli_addr, cli_len);
    OPENSSL_free(srv_pub);

    // Free DH key — no longer needed
    EVP_PKEY_free(clients[idx].dh_key);
    clients[idx].dh_key = NULL;

    // Allocate virtual IP  (IP ALLOCATOR — Phase 2)
    if (!ip_allocate(clients[idx].virtual_ip, sizeof(clients[idx].virtual_ip))) {
        fprintf(stderr, "[IP-POOL] Pool exhausted! Rejecting client %d\n", idx);
        session_free(idx);
        return;
    }
    printf("[IP-POOL] Assigned %s to session %d (%s:%d)\n",
           clients[idx].virtual_ip, idx,
           inet_ntoa(cli_addr->sin_addr), ntohs(cli_addr->sin_port));

    // Send IP assignment
    unsigned char ip_buf[ENC_BUF_SIZE];
    message_t *ip_msg = (message_t *)ip_buf;
    size_t ip_str_len = strlen(clients[idx].virtual_ip);
    ip_msg->type   = MSG_IP_ASSIGN;
    ip_msg->length = htons((unsigned short)ip_str_len);
    memcpy(ip_msg->data, clients[idx].virtual_ip, ip_str_len);
    sendto(sock, ip_buf, sizeof(message_t) + ip_str_len, 0,
           (struct sockaddr *)cli_addr, cli_len);

    clients[idx].handshake_done = 1;
    printf("[SESSION] Session %d fully established\n", idx);
}

// ─────────────────────────────────────────────
//  ROUTE TUN PACKET TO CORRECT CLIENT
// ─────────────────────────────────────────────
// Peek at destination IP in plain IP packet and find matching session
int find_client_by_dst_ip(const unsigned char *pkt, int pkt_len) {
    if (pkt_len < 20) return -1;
    // IP header: dst at offset 16-19
    char dst[INET_ADDRSTRLEN];
    snprintf(dst, sizeof(dst), "%d.%d.%d.%d",
             pkt[16], pkt[17], pkt[18], pkt[19]);
    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (clients[i].active && clients[i].handshake_done &&
            strcmp(clients[i].virtual_ip, dst) == 0) {
            return i;
        }
    }
    return -1;
}

// ─────────────────────────────────────────────
//  SIGNAL HANDLER
// ─────────────────────────────────────────────
void handle_signal(int sig) {
    (void)sig;
    printf("\n[SERVER] Shutting down...\n");
    running = 0;
}

// ─────────────────────────────────────────────
//  MAIN
// ─────────────────────────────────────────────
int main(int argc, char *argv[]) {
    // --setup-nat <wan_iface>  flag for Phase 4 NAT config
    if (argc >= 3 && strcmp(argv[1], "--setup-nat") == 0) {
        // Need TUN name to also add forward rules
        char tun_name[IFNAMSIZ] = "tun0";
        setup_nat(argv[2], tun_name);
        // Also auto-configure tun
        configure_tun(tun_name);
        printf("[NAT] NAT setup complete. Now run server normally: sudo ./vpnserver\n");
        return 0;
    }

    signal(SIGINT,  handle_signal);
    signal(SIGTERM, handle_signal);

    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();
    memset(clients, 0, sizeof(clients));
    memset(ip_pool_used, 0, sizeof(ip_pool_used));

    // Create TUN
    char tun_name[IFNAMSIZ] = "tun0";
    tun_fd_global = tun_alloc(tun_name);
    configure_tun(tun_name);

    // UDP socket
    sock_global = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock_global < 0) { perror("socket"); exit(1); }

    // Allow address reuse
    int opt = 1;
    setsockopt(sock_global, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in srv_addr;
    memset(&srv_addr, 0, sizeof(srv_addr));
    srv_addr.sin_family      = AF_INET;
    srv_addr.sin_addr.s_addr = INADDR_ANY;
    srv_addr.sin_port        = htons(PORT);
    if (bind(sock_global, (struct sockaddr *)&srv_addr, sizeof(srv_addr)) < 0) {
        perror("bind"); exit(1);
    }

    printf("╔══════════════════════════════════════════╗\n");
    printf("║   Lightweight VPN Server  (Full Build)   ║\n");
    printf("║   Phase 2+3+4  |  AES-256-GCM  |  DH    ║\n");
    printf("╚══════════════════════════════════════════╝\n");
    printf("[SERVER] Listening on UDP port %d\n", PORT);
    printf("[SERVER] Max clients: %d  |  IP pool: %s.%d-%d\n",
           MAX_CLIENTS, VPN_SUBNET, IP_POOL_START, IP_POOL_END);
    printf("[SERVER] Session timeout: %d seconds\n", SESSION_TIMEOUT);
    printf("[TIP]  For internet routing run: sudo ./vpnserver --setup-nat <wan_iface>\n\n");

    // Start session reaper thread (Phase 3)
    pthread_t reaper_tid;
    pthread_create(&reaper_tid, NULL, session_reaper, NULL);
    pthread_detach(reaper_tid);

    unsigned char buf[ENC_BUF_SIZE];
    unsigned char plain[BUFFER_SIZE];
    unsigned char cipher[BUFFER_SIZE + 64];

    while (running) {
        fd_set rfds;
        FD_ZERO(&rfds);
        FD_SET(sock_global, &rfds);
        FD_SET(tun_fd_global, &rfds);
        int maxfd = tun_fd_global > sock_global ? tun_fd_global : sock_global;

        struct timeval tv = {1, 0};   // 1s timeout to check running flag
        int ret = select(maxfd + 1, &rfds, NULL, NULL, &tv);
        if (ret < 0) { if (errno == EINTR) continue; perror("select"); continue; }

        // ── UDP → process ──
        if (FD_ISSET(sock_global, &rfds)) {
            struct sockaddr_in cli_addr;
            socklen_t cli_len = sizeof(cli_addr);
            int n = recvfrom(sock_global, buf, sizeof(buf), 0,
                             (struct sockaddr *)&cli_addr, &cli_len);
            if (n < (int)sizeof(message_t)) continue;

            message_t *msg = (message_t *)buf;
            unsigned short payload_len = ntohs(msg->length);

            pthread_mutex_lock(&clients_lock);
            int idx = session_find(&cli_addr);

            if (msg->type == MSG_HANDSHAKE_INIT) {
                if (idx >= 0) {
                    // Re-handshake: clean up old session
                    session_free(idx);
                }
                idx = session_new(&cli_addr, cli_len);
                if (idx < 0) {
                    fprintf(stderr, "[SERVER] No free session slots!\n");
                    pthread_mutex_unlock(&clients_lock);
                    continue;
                }
                printf("[SESSION] New client %s:%d → slot %d\n",
                       inet_ntoa(cli_addr.sin_addr), ntohs(cli_addr.sin_port), idx);
                handle_handshake(sock_global, idx, buf, n, &cli_addr, cli_len);
                pthread_mutex_unlock(&clients_lock);
                continue;
            }

            if (idx < 0 || !clients[idx].handshake_done) {
                pthread_mutex_unlock(&clients_lock);
                continue;   // unknown client or incomplete handshake
            }

            clients[idx].last_seen = time(NULL);

            if (msg->type == MSG_KEEPALIVE) {
                // Just update last_seen; no reply needed
                pthread_mutex_unlock(&clients_lock);
                continue;
            }

            if (msg->type == MSG_DISCONNECT) {
                printf("[SESSION] Client %d disconnected gracefully\n", idx);
                session_free(idx);
                pthread_mutex_unlock(&clients_lock);
                continue;
            }

            if (msg->type == MSG_DATA) {
                if (payload_len < AES_IV_SIZE + AES_TAG_SIZE) {
                    pthread_mutex_unlock(&clients_lock);
                    continue;
                }
                unsigned char iv[AES_IV_SIZE], tag[AES_TAG_SIZE];
                memcpy(iv,  msg->data,                AES_IV_SIZE);
                memcpy(tag, msg->data + AES_IV_SIZE,  AES_TAG_SIZE);
                int clen = payload_len - AES_IV_SIZE - AES_TAG_SIZE;
                if (clen <= 0) { pthread_mutex_unlock(&clients_lock); continue; }

                int plen = aes_gcm_decrypt(clients[idx].aes_key,
                                           msg->data + AES_IV_SIZE + AES_TAG_SIZE,
                                           clen, tag, iv, plain);
                if (plen > 0) {
                    write(tun_fd_global, plain, plen);
                    printf("[UDP→TUN] Session %d (%s): %d bytes decrypted\n",
                           idx, clients[idx].virtual_ip, plen);
                } else {
                    fprintf(stderr, "[CRYPTO] Decrypt failed for session %d\n", idx);
                }
            }
            pthread_mutex_unlock(&clients_lock);
        }

        // ── TUN → route to client ──
        if (FD_ISSET(tun_fd_global, &rfds)) {
            int n = read(tun_fd_global, plain, sizeof(plain));
            if (n <= 0) continue;

            pthread_mutex_lock(&clients_lock);
            int idx = find_client_by_dst_ip(plain, n);
            if (idx < 0) {
                // Broadcast to all connected clients (e.g. ARP, unknown dst)
                // For simplicity, drop unknown destinations
                pthread_mutex_unlock(&clients_lock);
                continue;
            }

            unsigned char iv[AES_IV_SIZE], tag[AES_TAG_SIZE];
            if (RAND_bytes(iv, AES_IV_SIZE) != 1) {
                pthread_mutex_unlock(&clients_lock);
                continue;
            }
            int clen = aes_gcm_encrypt(clients[idx].aes_key, plain, n,
                                       iv, cipher, tag);
            if (clen > 0) {
                message_t *dmsg = (message_t *)buf;
                int payload_len = AES_IV_SIZE + AES_TAG_SIZE + clen;
                dmsg->type   = MSG_DATA;
                dmsg->length = htons((unsigned short)payload_len);
                memcpy(dmsg->data,                           iv,     AES_IV_SIZE);
                memcpy(dmsg->data + AES_IV_SIZE,             tag,    AES_TAG_SIZE);
                memcpy(dmsg->data + AES_IV_SIZE + AES_TAG_SIZE, cipher, clen);
                sendto(sock_global, buf, sizeof(message_t) + payload_len, 0,
                       (struct sockaddr *)&clients[idx].addr, clients[idx].addr_len);
                printf("[TUN→UDP] Session %d (%s): %d bytes encrypted\n",
                       idx, clients[idx].virtual_ip, n);
            }
            pthread_mutex_unlock(&clients_lock);
        }
    }

    // Cleanup
    printf("[SERVER] Cleaning up sessions...\n");
    pthread_mutex_lock(&clients_lock);
    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (clients[i].active) session_free(i);
    }
    pthread_mutex_unlock(&clients_lock);

    close(tun_fd_global);
    close(sock_global);
    EVP_cleanup();
    CRYPTO_cleanup_all_ex_data();
    ERR_free_strings();
    printf("[SERVER] Goodbye.\n");
    return 0;
}