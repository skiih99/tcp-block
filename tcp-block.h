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

using namespace std;

void usage();
void get_attacker_ip(uint32_t* ipaddr,  char* dev);
void get_attacker_mac(uint8_t* macaddr, char* dev);