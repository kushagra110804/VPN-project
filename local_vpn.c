#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/select.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <linux/if_tun.h>
#include <errno.h>

int tun_alloc(char *dev) {
    struct ifreq ifr;
    int fd = open("/dev/net/tun", O_RDWR);
    if(fd < 0){ perror("open /dev/net/tun"); exit(1);}
    memset(&ifr,0,sizeof(ifr));
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
    strncpy(ifr.ifr_name, dev, IFNAMSIZ-1);
    ifr.ifr_name[IFNAMSIZ-1] = 0;
    if(ioctl(fd, TUNSETIFF,(void*)&ifr)<0){ perror("ioctl"); exit(1);}
    strcpy(dev,ifr.ifr_name);
    return fd;
}

int main() {
    char tun0_name[IFNAMSIZ] = "tun0";
    char tun1_name[IFNAMSIZ] = "tun1";

    int fd0 = tun_alloc(tun0_name);
    int fd1 = tun_alloc(tun1_name);

    printf("✅ Created TUN interfaces: %s (server), %s (client)\n", tun0_name, tun1_name);
    printf("Forwarding packets between tun0 and tun1...\n");

    char buffer[1500];
    while(1){
        fd_set readfds;
        FD_ZERO(&readfds);
        FD_SET(fd0, &readfds);
        FD_SET(fd1, &readfds);
        int maxfd = fd0 > fd1 ? fd0 : fd1;

        int ret = select(maxfd+1, &readfds, NULL, NULL, NULL);
        if(ret < 0){ perror("select"); exit(1); }

        // Packet from tun0 → write to tun1
        if(FD_ISSET(fd0, &readfds)){
            int n = read(fd0, buffer, sizeof(buffer));
            if(n < 0){ perror("read tun0"); exit(1);}
            printf("Packet %d bytes: tun0 -> tun1\n", n);
            write(fd1, buffer, n);
        }

        // Packet from tun1 → write to tun0
        if(FD_ISSET(fd1, &readfds)){
            int n = read(fd1, buffer, sizeof(buffer));
            if(n < 0){ perror("read tun1"); exit(1);}
            printf("Packet %d bytes: tun1 -> tun0\n", n);
            write(fd0, buffer, n);
        }
    }

    close(fd0);
    close(fd1);
    return 0;
}
