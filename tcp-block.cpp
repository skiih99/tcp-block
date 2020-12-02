#include "tcp-block.h"

void usage() {
    printf("syntax : tcp-block <interface> <pattern>\n");
	printf("sample : tcp-block ens32 \"Host: test.gilgil.net\"\n");
}

void get_my_mac(uint8_t* macaddr, char* dev) {
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

void block_process(pcap_t* handle, uint8_t* mac, uint8_t* pattern, int pattern_len) {
    while(1) {
        struct pcap_pkthdr* header;
        uint8_t* rcv_packet;

        int res = pcap_next_ex(handle, &header, (const u_char **)&rcv_packet);
        if (res == 0) continue;
        if (res == -1 || res == -2) {
            fprintf(stderr, "pcap_next_ex return error! %d(%s).\n", res, pcap_geterr(handle));
            break;
        }

        //if (!memcmp(rcv_packet + 6, mac, 6)) continue;

        struct ethhdr* ethhdr_pkt = (struct ethhdr *)rcv_packet;
        struct iphdr* iphdr_pkt = (struct iphdr *)(rcv_packet + ethhdr_size);
        if (ntohs(ethhdr_pkt->type) != 0x0800 || iphdr_pkt->protocol != 6) continue; // ipv4, tcp check

        int iphdr_len = ((iphdr_pkt->info) & 0x0F) * 4;
        int ippkt_len = ntohs(iphdr_pkt->len);
        struct tcphdr* tcphdr_pkt = (struct tcphdr *)(rcv_packet + ethhdr_size + iphdr_len);
        int tcphdr_len = (((tcphdr_pkt->len) & 0xF0) >> 4) * 4;
        int pkt_datalen = ippkt_len - iphdr_len - tcphdr_len;
        uint8_t* pkt_data = rcv_packet + ethhdr_size + iphdr_len + tcphdr_len; // TCP data in received pkt.

        if(!check_pattern(pkt_data, pkt_datalen, pattern, pattern_len)) continue;

        forward_sendpkt(handle, mac, rcv_packet, ethhdr_pkt, iphdr_pkt, tcphdr_pkt);
        backward_sendpkt(handle, mac, rcv_packet, ethhdr_pkt, iphdr_pkt, tcphdr_pkt);
        printf("success!\n");

    }
}

void forward_sendpkt(pcap_t* handle, uint8_t* mac, uint8_t* org_packet, struct ethhdr* org_eth, struct iphdr* org_ip, struct tcphdr* org_tcp) {
    int org_iplen = ((org_ip->info) & 0x0F) * 4;
    int org_tcplen = (((org_tcp->len) & 0xF0) >> 4) * 4;
    int org_totlen = ntohs(org_ip->len);
    int org_datalen = org_totlen - org_iplen - org_tcplen;

    uint8_t sendpkt[ethhdr_size + org_iplen + org_tcplen];
    // struct ethhdr* sendeth = (struct ethhdr*)sendpkt;
    // struct iphdr* sendip = (struct iphdr*)(sendpkt + ethhdr_size);
    // struct tcphdr* sendtcp = (struct tcphdr*)(sendpkt + ethhdr_size + org_iplen);
    struct ethhdr* sendeth = (struct ethhdr *)malloc(sizeof(struct ethhdr));
    struct iphdr* sendip = (struct iphdr *)malloc(sizeof(struct iphdr));
    struct tcphdr* sendtcp = (struct tcphdr *)malloc(sizeof(struct tcphdr));

    memcpy(sendeth, org_eth, ethhdr_size);
    // memcpy(sendip, org_ip, sizeof(struct iphdr));
    // memcpy(sendtcp, org_tcp, sizeof(struct tcphdr));

    memset(sendip, 0, sizeof(struct iphdr));
    memset(sendtcp, 0, sizeof(struct tcphdr));
    

    memcpy(sendeth->src_host, mac, 6);

    sendip->info = org_ip->info;
    sendip->len = htons(sizeof(struct iphdr) + sizeof(struct tcphdr));
    sendip->ttl = org_ip->ttl;
    sendip->protocol = org_ip->protocol;
    sendip->src_ip = org_ip->src_ip;
    sendip->dst_ip = org_ip->dst_ip;

    sendip->checksum = 0;
    uint16_t temp = htons(checksum_ip(sendip, sizeof(struct iphdr)));
    sendip->checksum = temp;

    sendtcp->src_port = org_tcp->src_port;
    sendtcp->dst_port = org_tcp->dst_port;
    sendtcp->seq = htonl(ntohl(org_tcp->seq) + org_datalen);
    sendtcp->ack = org_tcp->ack;
    sendtcp->len = org_tcp->len;
    sendtcp->flag = 0x04; // flag : 000100, rst
    sendtcp->window_size = org_tcp->window_size;

    sendtcp->checksum = 0;

    uint16_t imsitcp[org_tcplen / 2];
    memcpy(imsitcp, sendtcp, sizeof(struct tcphdr));

    
    uint16_t temp2 = htons(checksum_tcp(imsitcp, sendip, sizeof(struct tcphdr), 0));
    sendtcp->checksum = temp2;

    memcpy(sendpkt, sendeth, sizeof(struct ethhdr));
    memcpy(sendpkt+ethhdr_size, sendip, sizeof(struct iphdr));
    memcpy(sendpkt+ethhdr_size+org_iplen, sendtcp, sizeof(struct tcphdr));

    int res2 = pcap_sendpacket(handle, sendpkt, ethhdr_size + org_iplen + org_tcplen);
    if (res2 != 0) fprintf(stderr, "Send IP packet error!\n");

}

void backward_sendpkt(pcap_t* handle, uint8_t* mac, uint8_t* org_packet, struct ethhdr* org_eth, struct iphdr* org_ip, struct tcphdr* org_tcp) {
    int org_iplen = ((org_ip->info) & 0x0F) * 4;
    int org_tcplen = (((org_tcp->len) & 0xF0) >> 4) * 4;
    int org_totlen = ntohs(org_ip->len);
    int org_datalen = org_totlen - org_iplen - org_tcplen;

    uint8_t sendpkt[ethhdr_size + org_iplen + org_tcplen + 10];
    // struct ethhdr* sendeth = (struct ethhdr*)sendpkt;
    // struct iphdr* sendip = (struct iphdr*)(sendpkt + ethhdr_size);
    // struct tcphdr* sendtcp = (struct tcphdr*)(sendpkt + ethhdr_size + org_iplen);
    struct ethhdr* sendeth = (struct ethhdr *)malloc(sizeof(struct ethhdr));
    struct iphdr* sendip = (struct iphdr *)malloc(sizeof(struct iphdr));
    struct tcphdr* sendtcp = (struct tcphdr *)malloc(sizeof(struct tcphdr));

    memcpy(sendeth, org_eth, ethhdr_size);
    //memcpy(sendip, org_ip, sizeof(struct iphdr));
    //memcpy(sendtcp, org_tcp, sizeof(struct tcphdr));
    memset(sendip, 0, sizeof(struct iphdr));
    memset(sendtcp, 0, sizeof(struct tcphdr));

    memcpy(sendeth->src_host, mac, 6);
    memcpy(sendeth->dst_host, org_eth->src_host, 6);

    sendip->info = org_ip->info;
    sendip->len = htons(sizeof(struct iphdr) + sizeof(struct tcphdr) + 10);
    sendip->ttl = 128;
    sendip->protocol = org_ip->protocol;
    sendip->src_ip = org_ip->dst_ip;
    sendip->dst_ip = org_ip->src_ip;

    sendip->checksum = 0;
    uint16_t temp = htons(checksum_ip(sendip, sizeof(struct iphdr)));
    sendip->checksum = temp;

    sendtcp->src_port = org_tcp->dst_port;
    sendtcp->dst_port = org_tcp->src_port;
    sendtcp->seq = org_tcp->ack;
    sendtcp->ack = htonl(ntohl(org_tcp->seq) + org_datalen);
    sendtcp->len = org_tcp->len;
    sendtcp->flag = 0x11; // flag : 010001, fin, ack flag set
    sendtcp->checksum = 0;
    sendtcp->window_size = org_tcp->window_size;

    uint16_t imsitcp[(sizeof(struct tcphdr) + 10) / 2];

    char tmpmsg[11] = "Blocked!!!";
    memcpy(imsitcp, sendtcp, sizeof(struct tcphdr));
    memcpy(imsitcp + sizeof(struct tcphdr), tmpmsg, 10);

    uint16_t temp2 = htons(checksum_tcp(imsitcp, sendip, sizeof(struct tcphdr), 10));
    sendtcp->checksum = temp2;

    memcpy(sendpkt, sendeth, sizeof(struct ethhdr));
    memcpy(sendpkt+ethhdr_size, sendip, sizeof(struct iphdr));
    memcpy(sendpkt+ethhdr_size+org_iplen, sendtcp, sizeof(struct tcphdr));
    char msg1[11] = "Blocked!!!";
    printf("%s\n", msg1);
    memcpy(sendpkt+ethhdr_size+org_iplen+org_tcplen, msg1, 10);

    int res2 = pcap_sendpacket(handle, sendpkt, ethhdr_size + org_iplen + org_tcplen + 10);
    if (res2 != 0) fprintf(stderr, "Send IP packet error!\n");

}

bool check_pattern(uint8_t* data, int size, uint8_t* pattern, int pattern_len) {
    bool flag = false;
    for (int i = 0; i < size - 6; i++) {
        if (!memcmp(data + i, "Host: ", 6)) {
            if (!memcmp(data + i, pattern, pattern_len)) {
                flag = true;
                break;
            }
            else break;
        }
    }
    return flag;
}

uint16_t checksum_ip(struct iphdr *data, int len) {
    uint16_t* pkt16 = (uint16_t*) data;
    uint32_t result = 0;
    for(int i = 0; i < len/2; i++) {
        result += pkt16[i];
    }
    while(result >> 16) {
        result = (result & 0xFFFF) + (result >> 16);
    }
    return htons(~(uint16_t)result);
}

uint16_t checksum_tcp(uint16_t* tcp_data, struct iphdr *ip_data, int tcp_len, int data_len) {
    uint32_t result = 0;

    //pseudo header
    uint16_t* srcip;
    uint16_t* dstip;

    srcip = (uint16_t *)&(ip_data->src_ip);
    dstip = (uint16_t *)&(ip_data->dst_ip);
    
    for(int i = 0; i < 2; i++) {
        result += srcip[i];
        result += dstip[i];
    }
    result += htons(6); //protocol
    result += htons((uint16_t)(tcp_len + data_len));
    for(int i = 0; i < (tcp_len + data_len)/2; i++) {
        result += tcp_data[i];
    }

    while(result >> 16) {
        result = (result & 0xFFFF) + (result >> 16);
    }
    return htons(~(uint16_t)result);

}