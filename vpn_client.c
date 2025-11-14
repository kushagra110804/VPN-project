#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <linux/if_tun.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/dh.h>
#include <openssl/pem.h>
#include <openssl/bn.h>
#include <openssl/err.h>

#define PORT 5555
#define BUFFER_SIZE 1500
#define ENCRYPTED_BUFFER_SIZE (BUFFER_SIZE + 64)
#define AES_KEY_SIZE 32
#define AES_IV_SIZE 12
#define AES_TAG_SIZE 16
#define DH_KEY_SIZE 256

// Protocol message types
#define MSG_HANDSHAKE_INIT 0x01
#define MSG_HANDSHAKE_RESP 0x02
#define MSG_IP_ASSIGN 0x03
#define MSG_DATA 0x04

unsigned char aes_key[AES_KEY_SIZE];
int key_established = 0;
char assigned_ip[16] = {0};

typedef struct {
    unsigned char type;
    unsigned short length;
    unsigned char data[];
} __attribute__((packed)) message_t;

// Create TUN device
int tun_alloc(char *dev) {
    struct ifreq ifr;
    int fd = open("/dev/net/tun", O_RDWR);
    if (fd < 0) {
        perror("open /dev/net/tun");
        exit(1);
    }
    memset(&ifr, 0, sizeof(ifr));
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
    strncpy(ifr.ifr_name, dev, IFNAMSIZ - 1);
    ifr.ifr_name[IFNAMSIZ - 1] = 0;
    if (ioctl(fd, TUNSETIFF, (void *)&ifr) < 0) {
        perror("ioctl(TUNSETIFF)");
        close(fd);
        exit(1);
    }
    strcpy(dev, ifr.ifr_name);
    return fd;
}

// Generate Diffie-Hellman parameters and keys
EVP_PKEY* generate_dh_key() {
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_DH, NULL);
    if (!pctx) return NULL;
    
    if (EVP_PKEY_paramgen_init(pctx) <= 0) {
        EVP_PKEY_CTX_free(pctx);
        return NULL;
    }
    
    if (EVP_PKEY_CTX_set_dh_paramgen_prime_len(pctx, 2048) <= 0) {
        EVP_PKEY_CTX_free(pctx);
        return NULL;
    }
    
    EVP_PKEY *params = NULL;
    if (EVP_PKEY_paramgen(pctx, &params) <= 0) {
        EVP_PKEY_CTX_free(pctx);
        return NULL;
    }
    EVP_PKEY_CTX_free(pctx);
    
    EVP_PKEY_CTX *kctx = EVP_PKEY_CTX_new(params, NULL);
    if (!kctx) {
        EVP_PKEY_free(params);
        return NULL;
    }
    
    if (EVP_PKEY_keygen_init(kctx) <= 0) {
        EVP_PKEY_CTX_free(kctx);
        EVP_PKEY_free(params);
        return NULL;
    }
    
    EVP_PKEY *key = NULL;
    if (EVP_PKEY_keygen(kctx, &key) <= 0) {
        EVP_PKEY_CTX_free(kctx);
        EVP_PKEY_free(params);
        return NULL;
    }
    
    EVP_PKEY_CTX_free(kctx);
    EVP_PKEY_free(params);
    return key;
}

// Derive shared secret using DH
int derive_shared_secret(EVP_PKEY *privkey, unsigned char *peer_pubkey, size_t peer_pubkey_len, 
                         unsigned char *secret, size_t *secret_len) {
    EVP_PKEY *peer_key = EVP_PKEY_new();
    if (!peer_key) return -1;
    
    const unsigned char *p = peer_pubkey;
    if (!d2i_PUBKEY(&peer_key, &p, peer_pubkey_len)) {
        EVP_PKEY_free(peer_key);
        return -1;
    }
    
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(privkey, NULL);
    if (!ctx) {
        EVP_PKEY_free(peer_key);
        return -1;
    }
    
    if (EVP_PKEY_derive_init(ctx) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(peer_key);
        return -1;
    }
    
    if (EVP_PKEY_derive_set_peer(ctx, peer_key) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(peer_key);
        return -1;
    }
    
    if (EVP_PKEY_derive(ctx, NULL, secret_len) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(peer_key);
        return -1;
    }
    
    if (EVP_PKEY_derive(ctx, secret, secret_len) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(peer_key);
        return -1;
    }
    
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(peer_key);
    return 0;
}

// Decrypt data using AES-256-GCM
int aes_gcm_decrypt(unsigned char *ciphertext, int ciphertext_len,
                    unsigned char *tag, unsigned char *iv,
                    unsigned char *plaintext) {
    EVP_CIPHER_CTX *ctx;
    int len, plaintext_len, ret;

    if (!(ctx = EVP_CIPHER_CTX_new())) return -1;
    if (!EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL)) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, AES_IV_SIZE, NULL)) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    if (!EVP_DecryptInit_ex(ctx, NULL, NULL, aes_key, iv)) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    if (!EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len)) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    plaintext_len = len;
    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, AES_TAG_SIZE, tag)) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    ret = EVP_DecryptFinal_ex(ctx, plaintext + len, &len);
    EVP_CIPHER_CTX_free(ctx);
    
    if (ret > 0) {
        plaintext_len += len;
        return plaintext_len;
    }
    return -1;
}

// Encrypt data using AES-256-GCM
int aes_gcm_encrypt(unsigned char *plaintext, int plaintext_len,
                    unsigned char *iv, unsigned char *ciphertext,
                    unsigned char *tag) {
    EVP_CIPHER_CTX *ctx;
    int len, ciphertext_len;

    if (!(ctx = EVP_CIPHER_CTX_new())) return -1;
    if (!EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL)) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, AES_IV_SIZE, NULL)) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    if (!EVP_EncryptInit_ex(ctx, NULL, NULL, aes_key, iv)) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    if (!EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len)) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    ciphertext_len = len;
    if (!EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    ciphertext_len += len;
    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, AES_TAG_SIZE, tag)) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    EVP_CIPHER_CTX_free(ctx);
    return ciphertext_len;
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <server_ip>\n", argv[0]);
        return 1;
    }

    char tun_name[IFNAMSIZ] = "tun0";
    int tun_fd = tun_alloc(tun_name);
    printf("✅ Client TUN device %s created\n", tun_name);

    // Create UDP socket
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        perror("socket");
        exit(1);
    }

    // Setup server address
    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(PORT);
    if (inet_pton(AF_INET, argv[1], &server_addr.sin_addr) <= 0) {
        perror("inet_pton");
        exit(1);
    }

    printf("🔗 Connecting to server %s:%d\n", argv[1], PORT);
    printf("🔐 Initiating Diffie-Hellman key exchange...\n");

    // Generate DH key pair
    EVP_PKEY *dh_key = generate_dh_key();
    if (!dh_key) {
        fprintf(stderr, "Failed to generate DH key\n");
        exit(1);
    }

    // Serialize public key
    unsigned char *client_pubkey = NULL;
    int pubkey_len = i2d_PUBKEY(dh_key, &client_pubkey);
    if (pubkey_len < 0) {
        fprintf(stderr, "Failed to serialize public key\n");
        exit(1);
    }

    // Send handshake init
    unsigned char handshake[ENCRYPTED_BUFFER_SIZE];
    message_t *init_msg = (message_t *)handshake;
    init_msg->type = MSG_HANDSHAKE_INIT;
    init_msg->length = htons(pubkey_len);
    memcpy(init_msg->data, client_pubkey, pubkey_len);

    sendto(sock, handshake, sizeof(message_t) + pubkey_len, 0,
           (struct sockaddr *)&server_addr, sizeof(server_addr));
    
    OPENSSL_free(client_pubkey);
    printf("🤝 Sent handshake to server\n");

    unsigned char buffer[ENCRYPTED_BUFFER_SIZE];
    unsigned char decrypted_buffer[BUFFER_SIZE];

    // Wait for handshake response
    struct timeval tv = {5, 0}; // 5 second timeout
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    
    int n = recvfrom(sock, buffer, sizeof(buffer), 0, NULL, NULL);
    if (n <= 0) {
        fprintf(stderr, "Failed to receive handshake response\n");
        exit(1);
    }

    message_t *resp_msg = (message_t *)buffer;
    if (resp_msg->type == MSG_HANDSHAKE_RESP) {
        printf("🤝 Received handshake response from server\n");
        
        unsigned char *server_pubkey = resp_msg->data;
        size_t server_pubkey_len = ntohs(resp_msg->length);
        
        // Derive shared secret
        unsigned char shared_secret[DH_KEY_SIZE];
        size_t secret_len = sizeof(shared_secret);
        if (derive_shared_secret(dh_key, server_pubkey, server_pubkey_len, 
                                shared_secret, &secret_len) < 0) {
            fprintf(stderr, "Failed to derive shared secret\n");
            exit(1);
        }
        
        // Derive AES key from shared secret using SHA256
        EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
        EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL);
        EVP_DigestUpdate(mdctx, shared_secret, secret_len);
        EVP_DigestFinal_ex(mdctx, aes_key, NULL);
        EVP_MD_CTX_free(mdctx);
        
        key_established = 1;
        printf("🔑 Encryption key established\n");
    }

    // Wait for IP assignment
    n = recvfrom(sock, buffer, sizeof(buffer), 0, NULL, NULL);
    if (n > 0) {
        message_t *ip_msg = (message_t *)buffer;
        if (ip_msg->type == MSG_IP_ASSIGN) {
            int ip_len = ntohs(ip_msg->length);
            memcpy(assigned_ip, ip_msg->data, ip_len);
            assigned_ip[ip_len] = '\0';
            printf("📍 Assigned IP: %s\n", assigned_ip);
            printf("ℹ️  Configure the interface with: sudo ip addr add %s/24 dev %s\n", 
                   assigned_ip, tun_name);
            printf("ℹ️  Then bring it up with: sudo ip link set %s up\n", tun_name);
        }
    }

    // Reset timeout for normal operation
    tv.tv_sec = 0;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    printf("✅ VPN tunnel established with AES-256-GCM encryption\n");

    while (1) {
        fd_set readfds;
        FD_ZERO(&readfds);
        FD_SET(tun_fd, &readfds);
        FD_SET(sock, &readfds);
        int maxfd = tun_fd > sock ? tun_fd : sock;

        if (select(maxfd + 1, &readfds, NULL, NULL, NULL) < 0) {
            perror("select");
            continue;
        }

        // TUN -> UDP server (encrypted)
        if (FD_ISSET(tun_fd, &readfds)) {
            n = read(tun_fd, decrypted_buffer, sizeof(decrypted_buffer));
            if (n > 0 && key_established) {
                unsigned char iv[AES_IV_SIZE];
                unsigned char tag[AES_TAG_SIZE];
                unsigned char ciphertext[BUFFER_SIZE];
                
                RAND_bytes(iv, AES_IV_SIZE);
                
                int ciphertext_len = aes_gcm_encrypt(decrypted_buffer, n, iv, 
                                                     ciphertext, tag);
                if (ciphertext_len > 0) {
                    message_t *data_msg = (message_t *)buffer;
                    data_msg->type = MSG_DATA;
                    data_msg->length = htons(AES_IV_SIZE + AES_TAG_SIZE + ciphertext_len);
                    
                    memcpy(data_msg->data, iv, AES_IV_SIZE);
                    memcpy(data_msg->data + AES_IV_SIZE, tag, AES_TAG_SIZE);
                    memcpy(data_msg->data + AES_IV_SIZE + AES_TAG_SIZE, 
                           ciphertext, ciphertext_len);
                    
                    int total_len = sizeof(message_t) + AES_IV_SIZE + 
                                   AES_TAG_SIZE + ciphertext_len;
                    sendto(sock, buffer, total_len, 0,
                          (struct sockaddr *)&server_addr, sizeof(server_addr));
                    
                    printf("📤 Encrypted and forwarded %d bytes TUN -> UDP\n", n);
                }
            }
        }

        // UDP server -> TUN (decrypt)
        if (FD_ISSET(sock, &readfds)) {
            n = recvfrom(sock, buffer, sizeof(buffer), 0, NULL, NULL);
            if (n > 0) {
                message_t *msg = (message_t *)buffer;
                if (msg->type == MSG_DATA && key_established) {
                    unsigned char iv[AES_IV_SIZE];
                    unsigned char tag[AES_TAG_SIZE];
                    memcpy(iv, msg->data, AES_IV_SIZE);
                    memcpy(tag, msg->data + AES_IV_SIZE, AES_TAG_SIZE);
                    
                    int ciphertext_len = ntohs(msg->length) - AES_IV_SIZE - AES_TAG_SIZE;
                    int plaintext_len = aes_gcm_decrypt(
                        msg->data + AES_IV_SIZE + AES_TAG_SIZE,
                        ciphertext_len, tag, iv, decrypted_buffer);
                    
                    if (plaintext_len > 0) {
                        int written = write(tun_fd, decrypted_buffer, plaintext_len);
                        if (written > 0) {
                            printf("📥 Decrypted and forwarded %d bytes UDP -> TUN\n", written);
                        }
                    }
                }
            }
        }
    }

    EVP_PKEY_free(dh_key);
    close(tun_fd);
    close(sock);
    return 0;
}