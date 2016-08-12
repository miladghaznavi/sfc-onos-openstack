#include "parse.h"

#include <stdlib.h>
#include <stdio.h>
#include <inttypes.h>

#include <rte_ether.h>

int
parse_mac(const char *mac_str, struct ether_addr *mac) {
    int values[6];
    int i;
    
    if (6 == sscanf(mac_str, "%x:%x:%x:%x:%x:%x",
        &values[0], &values[1], &values[2],
        &values[3], &values[4], &values[5] ) )
    {
        /* convert to uint8_t */
        for (i = 0; i < 6; i++) {
            mac->addr_bytes[i] = (uint8_t) values[i];
        }
    } else {
        return 1;
    }
    
    return 0;
}

int
parse_ip(const char *ips, uint32_t* ip) {
    int values[4];
    int i;
    
    uint8_t * bytes = (uint8_t *) ip;
    
    if (4 == sscanf(ips, "%u.%u.%u.%u",
        &values[3], &values[2], &values[1], &values[0])) {
        /* convert to uint8_t */
        for (i = 0; i < 4; i++) {
            bytes[i] = (uint8_t) values[i];
        }
    } else {
        return 1;
    }
    
    return 0;
}