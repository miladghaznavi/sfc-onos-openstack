#ifndef ARP_SENDER_H_
#define ARP_SENDER_H_

#include <inttypes.h>
#include <libconfig.h>
#include <stdbool.h>

#include <rte_mbuf.h>
#include <rte_ethdev.h>

struct app_config;

struct arp_sender_t {
    int sending;
    struct transmit_t *tx;

    struct rte_mbuf *arp_sender_proto;

    /* Source and destination MAC address. */
    struct ether_addr src_mac;
    struct ether_addr dst_mac;
    
    /* Source and destination IP address. */
    uint32_t src_ip;
    uint32_t dst_ip;

    uint64_t timeout;

    struct rte_mempool *pkt_pool;
    struct rte_mempool *clone_pool;    
};

void
log_arp_sender(struct arp_sender_t *arp_sender);

void
poll_arp_sender(struct arp_sender_t *arp_sender);

int
get_arp_sender(config_setting_t *c_conf,
            struct app_config *appconfig, 
            struct arp_sender_t *arp_sender);


#endif /* ARP_SENDER_H_ */
