#include "tcp-block.h"

int main(int argc, char* argv[]) {
    uint8_t mac[6];
    uint8_t pattern[2048];

    if  (argc != 3) {
        usage();
        return -1;
    }

    char* dev = argv[1];
    int pattern_len = strlen(argv[2]);
    memcpy(pattern, argv[2], pattern_len);

    char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);

    if (handle == nullptr) {
        fprintf(stderr, "Device open error! %s return nullptr : %s\n", dev, errbuf);
        return -1;
    }

    get_my_mac(mac, dev);
    // for(int i=0; i<6; i++) printf("%x ", attack_mac[i]);

    //for(int i=0; i<pattern_len; i++) printf("%c", pattern[i]);

    block_process(handle, mac, pattern, pattern_len);
    
    pcap_close(handle);

    return 0;
}