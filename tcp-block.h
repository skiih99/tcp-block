#pragma once
#include <string.h>
#include <pcap.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <stdio.h>
#include <stdlib.h>

#define ethhdr_size 14

#pragma pack(push, 1)
struct ethhdr {
    uint8_t dst_host[6];
    uint8_t src_host[6];
    uint16_t type;
};

struct iphdr {
    uint8_t info;
    uint8_t tos;
    uint16_t len;
    uint16_t frag_id;
    uint16_t frag_offset;
    uint8_t ttl;
    uint8_t protocol;
    uint16_t checksum;
    uint32_t src_ip;
    uint32_t dst_ip;
};

struct tcphdr {
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t seq;
    uint32_t ack;
    uint8_t len;
    uint8_t flag;
    uint16_t window_size;
    uint16_t checksum;
    uint16_t urgent_pointer;
};
#pragma pack(pop)

using namespace std;

void usage();
void get_my_mac(uint8_t* macaddr, char* dev);
void block_process(pcap_t* handle, uint8_t* mac, uint8_t* pattern, int pattern_len);
void forward_sendpkt(pcap_t* handle, uint8_t* mac, uint8_t* org_packet, 
        struct ethhdr* org_eth, struct iphdr* org_ip, struct tcphdr* org_tcp);
void backward_sendpkt(pcap_t* handle, uint8_t* mac, uint8_t* org_packet, 
        struct ethhdr* org_eth, struct iphdr* org_ip, struct tcphdr* org_tcp);
bool check_pattern(uint8_t* data, int size, uint8_t* pattern, int pattern_len);
uint16_t checksum_ip(struct iphdr *data, int len);
uint16_t checksum_tcp(uint8_t* tcp_data, struct iphdr *ip_data, int tcp_len, int data_len);