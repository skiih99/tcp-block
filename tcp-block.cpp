#include "tcp-block.h"

void usage() {
    printf("syntax : tcp-block <interface> <pattern>\n");
	printf("sample : tcp-block ens32 \"Host: test.gilgil.net\"\n");
}

void get_attacker_ip(uint32_t* ipaddr,  char* dev) {
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
	struct ifreq ifr;
	struct sockaddr_in* sin;

    if (sock < 0) {
        fprintf(stderr, "Socket() error!\n");
        return;
    }

	ifr.ifr_addr.sa_family = AF_INET;
	strncpy(ifr.ifr_name, dev, IFNAMSIZ-1);
	ioctl(sock, SIOCGIFADDR, &ifr);

	sin = (struct sockaddr_in*)&ifr.ifr_addr;

    *ipaddr = (uint32_t) sin->sin_addr.s_addr;
    
	close(sock);
}

void get_attacker_mac(uint8_t* macaddr, char* dev) {
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
	struct ifreq ifr;

    if (sock < 0) {
        fprintf(stderr, "Socket() error!\n");
        return;
    }

    strncpy(ifr.ifr_name, dev, IFNAMSIZ);
    ioctl(sock, SIOCGIFHWADDR, &ifr);
    
    memcpy(macaddr, ifr.ifr_hwaddr.sa_data, 6);
    close(sock);   
}