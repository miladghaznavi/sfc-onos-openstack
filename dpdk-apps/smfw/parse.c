#include "parse.h"

#include "components/wrapping.h"

#include <stdlib.h>
#include <stdio.h>
#include <inttypes.h>

#include <rte_ip.h>
#include <rte_ether.h>

#define RTE_LOGTYPE_PARSER RTE_LOGTYPE_USER1

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

void
print_packet_hex(struct rte_mbuf* m) {
    unsigned pos = 0;

    while (m != NULL) {
        uint8_t *byte = rte_pktmbuf_mtod(m, uint8_t *);
        for (unsigned i = 0; i < m->data_len; i++) {
            if (pos++ % 4 == 0) printf("\n");
            printf("%02x ", byte[i]);

        }
        m = m->next;
    }
    printf("\n");
}

void
print_packet(struct rte_mbuf* m, int has_meta) {
    struct ether_hdr *eth = rte_pktmbuf_mtod(m, struct ether_hdr *);
    struct ipv4_hdr *ip = rte_pktmbuf_mtod_offset(m, struct ipv4_hdr *, sizeof(struct ether_hdr));

    RTE_LOG(INFO, PARSER, "--------------------------\n");
    RTE_LOG(INFO, PARSER, "| "FORMAT_MAC" | "FORMAT_MAC" |\n", ARG_V_MAC(eth->s_addr), ARG_V_MAC(eth->d_addr));
    RTE_LOG(INFO, PARSER, "| %"PRIu16" |\n", eth->ether_type);
    RTE_LOG(INFO, PARSER, "| %"PRIu8" | %"PRIu8" | %"PRIu16" |\n", ip->version_ihl,ip->type_of_service,ip->total_length); 
    RTE_LOG(INFO, PARSER, "| %"PRIu16" | %"PRIu16" |\n", ip->packet_id, ip->fragment_offset);
    RTE_LOG(INFO, PARSER, "| %"PRIu8" | %"PRIu8" | %"PRIu16"\n", ip->time_to_live, ip->next_proto_id, ip->hdr_checksum); 
    RTE_LOG(INFO, PARSER, "| "FORMAT_IP" |\n", ARG_V_IP(ip->src_addr));
    RTE_LOG(INFO, PARSER, "| "FORMAT_IP" |\n", ARG_V_IP(ip->dst_addr));
    if (has_meta == 1) RTE_LOG(INFO, PARSER, "| %"PRIu64" |\n", wrapper_get_data(m)->decissions);
    RTE_LOG(INFO, PARSER, "--------------------------\n");

}