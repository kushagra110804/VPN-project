// vpn_server_full.c
// Complete Lightweight VPN Server - Phase 2 + 3 + 4
// AWS EC2 Ready Build
//
// Compile: gcc vpn_server_full.c -o vpnserver -lssl -lcrypto -lpthread
// Run as root: sudo ./vpnserver
// Setup NAT (run once): sudo ./vpnserver --setup-nat eth0

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
#include <syslog.h>

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

#define MAX_CLIENTS       32
#define SESSION_TIMEOUT   300         // seconds of inactivity before cleanup
#define KEEPALIVE_INTERVAL 30

#define VPN_SUBNET        "10.8.0"
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
//  LOGGING — goes to both stdout and syslog
// ─────────────────────────────────────────────
static int use_syslog = 0;

#define LOG(fmt, ...) do { \
    printf("[VPN] " fmt "\n", ##__VA_ARGS__); \
    if (use_syslog) syslog(LOG_INFO, fmt, ##__VA_ARGS__); \
} while(0)

#define LOG_ERROR(fmt, ...) do { \
    fprintf(stderr, "[VPN-ERR] " fmt "\n", ##__VA_ARGS__); \
    if (use_syslog) syslog(LOG_ERR, fmt, ##__VA_ARGS__); \
} while(0)

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
    char           virtual_ip[32];
    time_t         last_seen;
    EVP_PKEY      *dh_key;
    int            handshake_done;
} client_session_t;

// Global state
static client_session_t clients[MAX_CLIENTS];
static pthread_mutex_t  clients_lock = PTHREAD_MUTEX_INITIALIZER;
static int ip_pool_used[IP_POOL_END + 1];
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
    LOG("Created TUN interface: %s", dev);
    return fd;
}

// ─────────────────────────────────────────────
//  MODULE: IP ALLOCATOR
// ─────────────────────────────────────────────
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
    return 0;
}

void ip_release(const char *ip) {
    const char *last_dot = strrchr(ip, '.');
    if (!last_dot) return;
    int octet = atoi(last_dot + 1);
    if (octet >= IP_POOL_START && octet <= IP_POOL_END) {
        pthread_mutex_lock(&clients_lock);
        ip_pool_used[octet] = 0;
        pthread_mutex_unlock(&clients_lock);
        LOG("IP-POOL released: %s", ip);
    }
}

// ─────────────────────────────────────────────
//  MODULE: SESSION MANAGER
// ─────────────────────────────────────────────
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

int session_new(const struct sockaddr_in *addr, socklen_t addr_len) {
    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (!clients[i].active) {
            memset(&clients[i], 0, sizeof(clients[i]));
            clients[i].active    = 1;
            clients[i].addr      = *addr;
            clients[i].addr_len  = addr_len;
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
    LOG("Freed session %d (was %s)", idx, clients[idx].virtual_ip);
    memset(&clients[idx], 0, sizeof(clients[idx]));
}

void *session_reaper(void *arg) {
    (void)arg;
    while (running) {
        sleep(30);
        time_t now = time(NULL);
        pthread_mutex_lock(&clients_lock);
        for (int i = 0; i < MAX_CLIENTS; i++) {
            if (clients[i].active && (now - clients[i].last_seen) > SESSION_TIMEOUT) {
                LOG("REAPER: Session %d (%s) timed out", i, clients[i].virtual_ip);
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
//  AWS: uses IMDSv2 to auto-detect WAN interface
// ─────────────────────────────────────────────
// Auto-detect primary WAN interface (works on both AWS and bare metal)
void detect_wan_interface(char *iface, size_t iface_len) {
    FILE *fp = popen("ip route show default | awk '/default/ {print $5}' | head -1", "r");
    if (fp) {
        if (fgets(iface, iface_len, fp)) {
            iface[strcspn(iface, "\n")] = 0;
        }
        pclose(fp);
    }
    // Fallback common names
    if (strlen(iface) == 0) {
        // Try AWS typical interface names
        const char *candidates[] = {"ens5", "eth0", "enp0s3", NULL};
        for (int i = 0; candidates[i]; i++) {
            char check[128];
            snprintf(check, sizeof(check), "ip link show %s > /dev/null 2>&1", candidates[i]);
            if (system(check) == 0) {
                strncpy(iface, candidates[i], iface_len - 1);
                break;
            }
        }
    }
}

void setup_nat(const char *wan_iface, const char *tun_iface) {
    char cmd[512];
    LOG("NAT: Enabling IP forwarding...");
    system("echo 1 > /proc/sys/net/ipv4/ip_forward");
    system("sysctl -w net.ipv4.ip_forward=1 > /dev/null 2>&1");
    // Persist across reboots
    system("grep -q 'net.ipv4.ip_forward' /etc/sysctl.conf || "
           "echo 'net.ipv4.ip_forward=1' >> /etc/sysctl.conf");

    LOG("NAT: Adding iptables MASQUERADE on %s...", wan_iface);
    snprintf(cmd, sizeof(cmd),
             "iptables -t nat -C POSTROUTING -s 10.8.0.0/24 -o %s -j MASQUERADE 2>/dev/null || "
             "iptables -t nat -A POSTROUTING -s 10.8.0.0/24 -o %s -j MASQUERADE",
             wan_iface, wan_iface);
    system(cmd);

    snprintf(cmd, sizeof(cmd),
             "iptables -C FORWARD -i %s -o %s -j ACCEPT 2>/dev/null || "
             "iptables -A FORWARD -i %s -o %s -j ACCEPT",
             tun_iface, wan_iface, tun_iface, wan_iface);
    system(cmd);
    snprintf(cmd, sizeof(cmd),
             "iptables -C FORWARD -i %s -o %s -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || "
             "iptables -A FORWARD -i %s -o %s -m state --state RELATED,ESTABLISHED -j ACCEPT",
             wan_iface, tun_iface, wan_iface, tun_iface);
    system(cmd);

    // Save iptables rules (so they survive reboot)
    system("which iptables-save > /dev/null 2>&1 && iptables-save > /etc/iptables/rules.v4 2>/dev/null || true");
    system("which netfilter-persistent > /dev/null 2>&1 && netfilter-persistent save 2>/dev/null || true");

    LOG("NAT: ✅ Configured — VPN clients can reach the internet via %s", wan_iface);
}

void configure_tun(const char *dev) {
    char cmd[256];
    snprintf(cmd, sizeof(cmd),
             "ip addr show %s | grep -q '%s' || ip addr add %s/24 dev %s",
             dev, VPN_SERVER_IP, VPN_SERVER_IP, dev);
    system(cmd);
    snprintf(cmd, sizeof(cmd), "ip link set %s up", dev);
    system(cmd);
    // Raise MTU slightly lower than default to avoid fragmentation over UDP tunnel
    snprintf(cmd, sizeof(cmd), "ip link set %s mtu 1420", dev);
    system(cmd);
    LOG("TUN %s configured: %s/24  MTU=1420", dev, VPN_SERVER_IP);
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
        LOG_ERROR("Truncated handshake from client %d", idx);
        return;
    }

    clients[idx].dh_key = generate_dh_key();
    if (!clients[idx].dh_key) { LOG_ERROR("DH key generation failed"); return; }

    unsigned char shared_secret[DH_KEY_SIZE];
    size_t secret_len = sizeof(shared_secret);
    if (derive_shared_secret(clients[idx].dh_key, msg->data, payload_len,
                             shared_secret, &secret_len) < 0) {
        LOG_ERROR("Failed to derive shared secret for session %d", idx);
        return;
    }
    derive_aes_key(shared_secret, secret_len, clients[idx].aes_key);
    LOG("Session %d: AES-256-GCM key derived", idx);

    unsigned char *srv_pub = NULL;
    int srv_pub_len = i2d_PUBKEY(clients[idx].dh_key, &srv_pub);
    if (srv_pub_len <= 0 || srv_pub_len > (int)(ENC_BUF_SIZE - sizeof(message_t))) {
        LOG_ERROR("Server pubkey serialization failed");
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

    EVP_PKEY_free(clients[idx].dh_key);
    clients[idx].dh_key = NULL;

    if (!ip_allocate(clients[idx].virtual_ip, sizeof(clients[idx].virtual_ip))) {
        LOG_ERROR("IP pool exhausted! Rejecting client %d", idx);
        session_free(idx);
        return;
    }
    LOG("IP-POOL assigned %s to session %d (%s:%d)",
        clients[idx].virtual_ip, idx,
        inet_ntoa(cli_addr->sin_addr), ntohs(cli_addr->sin_port));

    unsigned char ip_buf[ENC_BUF_SIZE];
    message_t *ip_msg = (message_t *)ip_buf;
    size_t ip_str_len = strlen(clients[idx].virtual_ip);
    ip_msg->type   = MSG_IP_ASSIGN;
    ip_msg->length = htons((unsigned short)ip_str_len);
    memcpy(ip_msg->data, clients[idx].virtual_ip, ip_str_len);
    sendto(sock, ip_buf, sizeof(message_t) + ip_str_len, 0,
           (struct sockaddr *)cli_addr, cli_len);

    clients[idx].handshake_done = 1;
    LOG("Session %d fully established", idx);
}

// ─────────────────────────────────────────────
//  ROUTE TUN PACKET TO CORRECT CLIENT
// ─────────────────────────────────────────────
int find_client_by_dst_ip(const unsigned char *pkt, int pkt_len) {
    if (pkt_len < 20) return -1;
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
    LOG("Caught signal, shutting down...");
    running = 0;
}

// ─────────────────────────────────────────────
//  PRINT STATUS
// ─────────────────────────────────────────────
void print_active_sessions(void) {
    pthread_mutex_lock(&clients_lock);
    int count = 0;
    for (int i = 0; i < MAX_CLIENTS; i++)
        if (clients[i].active) count++;
    LOG("Active sessions: %d / %d", count, MAX_CLIENTS);
    pthread_mutex_unlock(&clients_lock);
}

void *status_printer(void *arg) {
    (void)arg;
    while (running) {
        sleep(60);
        print_active_sessions();
    }
    return NULL;
}

// ─────────────────────────────────────────────
//  MAIN
// ─────────────────────────────────────────────
int main(int argc, char *argv[]) {
    // --setup-nat [wan_iface]  — auto-detects if not given
    if (argc >= 2 && strcmp(argv[1], "--setup-nat") == 0) {
        char tun_name[IFNAMSIZ] = "tun0";
        char wan[64] = {0};
        if (argc >= 3) {
            strncpy(wan, argv[2], sizeof(wan) - 1);
        } else {
            detect_wan_interface(wan, sizeof(wan));
            if (strlen(wan) == 0) {
                fprintf(stderr, "[ERR] Could not auto-detect WAN interface. "
                                "Pass it explicitly: --setup-nat eth0\n");
                return 1;
            }
            printf("[NAT] Auto-detected WAN interface: %s\n", wan);
        }
        setup_nat(wan, tun_name);
        configure_tun(tun_name);
        printf("[NAT] Setup complete. Run server: sudo ./vpnserver\n");
        return 0;
    }

    // --syslog flag for systemd / daemon mode
    if (argc >= 2 && strcmp(argv[1], "--syslog") == 0) {
        use_syslog = 1;
        openlog("vpnserver", LOG_PID, LOG_DAEMON);
    }

    signal(SIGINT,  handle_signal);
    signal(SIGTERM, handle_signal);
    signal(SIGPIPE, SIG_IGN);   // ignore broken pipe

    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();
    memset(clients, 0, sizeof(clients));
    memset(ip_pool_used, 0, sizeof(ip_pool_used));

    // Create and configure TUN
    char tun_name[IFNAMSIZ] = "tun0";
    tun_fd_global = tun_alloc(tun_name);
    configure_tun(tun_name);

    // UDP socket
    sock_global = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock_global < 0) { perror("socket"); exit(1); }

    int opt = 1;
    setsockopt(sock_global, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    // Increase socket buffers for throughput
    int bufsize = 4 * 1024 * 1024;  // 4 MB
    setsockopt(sock_global, SOL_SOCKET, SO_RCVBUF, &bufsize, sizeof(bufsize));
    setsockopt(sock_global, SOL_SOCKET, SO_SNDBUF, &bufsize, sizeof(bufsize));

    struct sockaddr_in srv_addr;
    memset(&srv_addr, 0, sizeof(srv_addr));
    srv_addr.sin_family      = AF_INET;
    srv_addr.sin_addr.s_addr = INADDR_ANY;
    srv_addr.sin_port        = htons(PORT);
    if (bind(sock_global, (struct sockaddr *)&srv_addr, sizeof(srv_addr)) < 0) {
        perror("bind"); exit(1);
    }

    printf("╔══════════════════════════════════════════╗\n");
    printf("║   Lightweight VPN Server  (AWS Build)    ║\n");
    printf("║   Phase 2+3+4  |  AES-256-GCM  |  DH    ║\n");
    printf("╚══════════════════════════════════════════╝\n");
    LOG("Listening on UDP port %d", PORT);
    LOG("Max clients: %d  |  IP pool: %s.%d-%d",
        MAX_CLIENTS, VPN_SUBNET, IP_POOL_START, IP_POOL_END);
    LOG("Session timeout: %d seconds", SESSION_TIMEOUT);
    printf("[TIP] For internet routing: sudo ./vpnserver --setup-nat\n\n");

    // Background threads
    pthread_t reaper_tid, status_tid;
    pthread_create(&reaper_tid, NULL, session_reaper, NULL);
    pthread_detach(reaper_tid);
    pthread_create(&status_tid, NULL, status_printer, NULL);
    pthread_detach(status_tid);

    unsigned char buf[ENC_BUF_SIZE];
    unsigned char plain[BUFFER_SIZE];
    unsigned char cipher[BUFFER_SIZE + 64];

    while (running) {
        fd_set rfds;
        FD_ZERO(&rfds);
        FD_SET(sock_global, &rfds);
        FD_SET(tun_fd_global, &rfds);
        int maxfd = tun_fd_global > sock_global ? tun_fd_global : sock_global;

        struct timeval tv = {1, 0};
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
                if (idx >= 0) session_free(idx);
                idx = session_new(&cli_addr, cli_len);
                if (idx < 0) {
                    LOG_ERROR("No free session slots!");
                    pthread_mutex_unlock(&clients_lock);
                    continue;
                }
                LOG("New client %s:%d → slot %d",
                    inet_ntoa(cli_addr.sin_addr), ntohs(cli_addr.sin_port), idx);
                handle_handshake(sock_global, idx, buf, n, &cli_addr, cli_len);
                pthread_mutex_unlock(&clients_lock);
                continue;
            }

            if (idx < 0 || !clients[idx].handshake_done) {
                pthread_mutex_unlock(&clients_lock);
                continue;
            }

            clients[idx].last_seen = time(NULL);

            if (msg->type == MSG_KEEPALIVE) {
                pthread_mutex_unlock(&clients_lock);
                continue;
            }

            if (msg->type == MSG_DISCONNECT) {
                LOG("Client %d disconnected gracefully", idx);
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
                memcpy(iv,  msg->data,               AES_IV_SIZE);
                memcpy(tag, msg->data + AES_IV_SIZE,  AES_TAG_SIZE);
                int clen = payload_len - AES_IV_SIZE - AES_TAG_SIZE;
                if (clen <= 0) { pthread_mutex_unlock(&clients_lock); continue; }

                int plen = aes_gcm_decrypt(clients[idx].aes_key,
                                           msg->data + AES_IV_SIZE + AES_TAG_SIZE,
                                           clen, tag, iv, plain);
                if (plen > 0) {
                    write(tun_fd_global, plain, plen);
                } else {
                    LOG_ERROR("Decrypt failed for session %d", idx);
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
            if (idx < 0) { pthread_mutex_unlock(&clients_lock); continue; }

            unsigned char iv[AES_IV_SIZE], tag[AES_TAG_SIZE];
            if (RAND_bytes(iv, AES_IV_SIZE) != 1) {
                pthread_mutex_unlock(&clients_lock);
                continue;
            }
            int clen = aes_gcm_encrypt(clients[idx].aes_key, plain, n, iv, cipher, tag);
            if (clen > 0) {
                message_t *dmsg = (message_t *)buf;
                int plen = AES_IV_SIZE + AES_TAG_SIZE + clen;
                dmsg->type   = MSG_DATA;
                dmsg->length = htons((unsigned short)plen);
                memcpy(dmsg->data,                              iv,     AES_IV_SIZE);
                memcpy(dmsg->data + AES_IV_SIZE,                tag,    AES_TAG_SIZE);
                memcpy(dmsg->data + AES_IV_SIZE + AES_TAG_SIZE, cipher, clen);
                sendto(sock_global, buf, sizeof(message_t) + plen, 0,
                       (struct sockaddr *)&clients[idx].addr, clients[idx].addr_len);
            }
            pthread_mutex_unlock(&clients_lock);
        }
    }

    // Cleanup
    LOG("Cleaning up %d sessions...", MAX_CLIENTS);
    pthread_mutex_lock(&clients_lock);
    for (int i = 0; i < MAX_CLIENTS; i++)
        if (clients[i].active) session_free(i);
    pthread_mutex_unlock(&clients_lock);

    close(tun_fd_global);
    close(sock_global);
    EVP_cleanup();
    CRYPTO_cleanup_all_ex_data();
    ERR_free_strings();
    if (use_syslog) closelog();
    LOG("Goodbye.");
    return 0;
}
