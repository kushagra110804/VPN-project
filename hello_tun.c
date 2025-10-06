#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <linux/if_tun.h>
#include <errno.h>

// Function to create a TUN device
int tun_alloc(char *dev, int flags) {
    struct ifreq ifr;
    int fd;

    // Open the clone device
    if ((fd = open("/dev/net/tun", O_RDWR)) < 0) {
        perror("Opening /dev/net/tun");
        return -1;
    }

    memset(&ifr, 0, sizeof(ifr));
    ifr.ifr_flags = flags;  // IFF_TUN or IFF_TAP | IFF_NO_PI

    if (*dev) {
        strncpy(ifr.ifr_name, dev, IFNAMSIZ - 1);
        ifr.ifr_name[IFNAMSIZ - 1] = '\0'; // Ensure null termination
    }

    if (ioctl(fd, TUNSETIFF, (void *)&ifr) < 0) {
        perror("ioctl(TUNSETIFF)");
        close(fd);
        return -1;
    }

    strcpy(dev, ifr.ifr_name); // Copy actual name back
    return fd;
}

int main() {
    char tun_name[IFNAMSIZ] = "tun0";
    int tun_fd = tun_alloc(tun_name, IFF_TUN | IFF_NO_PI);

    if (tun_fd < 0) {
        fprintf(stderr, "Failed to create TUN device. Are you running as root?\n");
        exit(1);
    }

    printf("✅ TUN device %s created successfully.\n", tun_name);
    printf("You can now assign an IP and bring it up:\n");
    printf("sudo ip addr add 10.0.0.1/24 dev %s\n", tun_name);
    printf("sudo ip link set dev %s up\n", tun_name);

    // Keep the program running so you can interact with tun0
    printf("Press Ctrl+C to exit.\n");

    while (1) {
        char buffer[1500];
        int nread = read(tun_fd, buffer, sizeof(buffer));
        if (nread < 0) {
            perror("Reading from TUN interface");
            close(tun_fd);
            exit(1);
        }
        printf("Read %d bytes from %s\n", nread, tun_name);
    }

    close(tun_fd);
    return 0;
}
