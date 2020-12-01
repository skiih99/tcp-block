#include "tcp-block.h"

int main(int argc, char* argv[]) {
    uint32_t attack_ip;
    uint8_t attack_mac[6];

    get_attacker_ip(&attack_ip, argv[1]);
    // uint8_t* tmp;
    // tmp = (uint8_t *)&attack_ip;
    // for(int i=0; i<4; i++) printf("%d ", tmp[i]);
    get_attacker_mac(attack_mac, argv[1]);
    //for(int i=0; i<6; i++) printf("%x ", attack_mac[i]);
}