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

#define PORT 5555
#define BUFFER_SIZE 1500

// Allocate a TUN device
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

int main() {
    char tun_name[IFNAMSIZ] = "tun0";
    int tun_fd = tun_alloc(tun_name);
    printf("✅ Server TUN device %s created\n", tun_name);

    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        perror("socket");
        exit(1);
    }

    struct sockaddr_in server_addr, client_addr;
    socklen_t client_len = sizeof(client_addr);
    int client_known = 0;  // Flag to check if client is known

    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(PORT);

    if (bind(sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("bind");
        exit(1);
    }
    printf("📡 Server listening on UDP port %d\n", PORT);

    char buffer[BUFFER_SIZE];
    while (1) {
        fd_set readfds;
        FD_ZERO(&readfds);
        FD_SET(tun_fd, &readfds);
        FD_SET(sock, &readfds);
        int maxfd = tun_fd > sock ? tun_fd : sock;

        if (select(maxfd + 1, &readfds, NULL, NULL, NULL) < 0) {
            perror("select");
            exit(1);
        }

        // UDP client -> TUN
        if (FD_ISSET(sock, &readfds)) {
            int n = recvfrom(sock, buffer, sizeof(buffer), 0,
                             (struct sockaddr *)&client_addr, &client_len);
            if (n > 0) {
                client_known = 1; // now we know client address
                int written = write(tun_fd, buffer, n);
                if (written < 0) perror("write to tun");
                else printf("📥 Forwarded %d bytes UDP -> TUN\n", written);
            }
        }

        // TUN -> UDP client (only if we know client)
        if (FD_ISSET(tun_fd, &readfds)) {
            int n = read(tun_fd, buffer, sizeof(buffer));
            if (n > 0) {
                if (client_known) {
                    int sent = sendto(sock, buffer, n, 0,
                                      (struct sockaddr *)&client_addr, client_len);
                    if (sent < 0) perror("sendto");
                    else printf("📤 Forwarded %d bytes TUN -> UDP\n", sent);
                } else {
                    printf("⚠️ Got packet from TUN but no client known yet, dropping.\n");
                }
            }
        }
    }

    close(tun_fd);
    close(sock);
    return 0;
}
