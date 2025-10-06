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

        // TUN -> UDP server
        if (FD_ISSET(tun_fd, &readfds)) {
            int n = read(tun_fd, buffer, sizeof(buffer));
            if (n < 0) {
                perror("read from tun");
                continue;
            }
            int sent = sendto(sock, buffer, n, 0,
                              (struct sockaddr *)&server_addr, sizeof(server_addr));
            if (sent < 0) {
                perror("sendto");
            } else {
                printf("📤 Forwarded %d bytes TUN -> UDP (to %s)\n", sent, argv[1]);
            }
        }

        // UDP server -> TUN
        if (FD_ISSET(sock, &readfds)) {
            int n = recvfrom(sock, buffer, sizeof(buffer), 0, NULL, NULL);
            if (n < 0) {
                perror("recvfrom");
                continue;
            }
            int written = write(tun_fd, buffer, n);
            if (written < 0) {
                perror("write to tun");
            } else {
                printf("📥 Forwarded %d bytes UDP -> TUN\n", written);
            }
        }
    }

    close(tun_fd);
    close(sock);
    return 0;
}
