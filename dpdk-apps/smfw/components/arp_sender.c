#include "arp_sender.h"

#include <rte_byteorder.h>
#include <rte_mbuf.h>
#include <rte_ether.h>
#include <rte_ethdev.h>
#include <rte_arp.h>
#include <rte_ip.h>

#include "../config.h"
#include "../rxtx.h"
#include "../parse.h"
#include "../init.h"

#define RTE_LOGTYPE_ARP_SENDER RTE_LOGTYPE_USER1

static struct rte_mbuf *
gen_arp_packet(struct arp_sender_t *arp_sender) {
	struct rte_mbuf *packet = rte_pktmbuf_alloc(arp_sender->pkt_pool);
	
	packet->data_len = sizeof(struct ether_hdr) + sizeof(struct arp_hdr);
	packet->pkt_len = packet->data_len;

	struct ether_hdr *eth = rte_pktmbuf_mtod(packet, struct ether_hdr *);
	struct arp_hdr *arp = rte_pktmbuf_mtod_offset(packet, struct arp_hdr *, sizeof(struct ether_hdr));
//	struct arp_hdr *arp = rte_pktmbuf_mtod(packet, struct arp_hdr *);
	struct arp_ipv4 *arp_payload = &arp->arp_data;

	ether_addr_copy(&arp_sender->tx->send_port_mac, &eth->s_addr);
	ether_addr_copy(&arp_sender->dst_mac, &eth->d_addr);
	eth->ether_type = rte_cpu_to_be_16(ETHER_TYPE_ARP);

	arp->arp_hrd  = rte_cpu_to_be_16(ARP_HRD_ETHER);
	arp->arp_pro  = rte_cpu_to_be_16(0x0800);
	arp->arp_hln  = 6;
	arp->arp_pln  = 4;
	arp->arp_op  = rte_cpu_to_be_16(ARP_OP_REPLY);

	ether_addr_copy(&arp_sender->tx->send_port_mac, &arp_payload->arp_sha);
	arp_payload->arp_sip = rte_cpu_to_be_32(arp_sender->src_ip);
	ether_addr_copy(&arp_sender->dst_mac, &arp_payload->arp_tha);
	arp_payload->arp_tip = rte_cpu_to_be_32(arp_sender->dst_ip);
	print_packet_hex(packet);
	return packet;
}

void
log_arp_sender(struct arp_sender_t *arp_sender) {

}

void
poll_arp_sender(struct arp_sender_t *arp_sender) {
	// Log ARP sender to prevent recursion
	if (arp_sender->sending == 0) arp_sender->sending = 1;
	else  return;

	RTE_LOG(INFO, ARP_SENDER, "send arp!\n");
	struct rte_mbuf *packet = gen_arp_packet(arp_sender);

	int send = 0;
	while (send == 0)
		send += tx_put(arp_sender->tx, &packet, 1);

	arp_sender->sending = 0;
}

static int
read_mac(config_setting_t *arp_conf, const char *name, struct ether_addr *mac) {
    const char *omac;
    if (config_setting_lookup_string(arp_conf, name, &omac) == CONFIG_TRUE) {
        if (parse_mac(omac, mac) != 0) {
            RTE_LOG(ERR, ARP_SENDER, "Source MAC has wrong format.\n");
            return 1;
        }
    } else {
        RTE_LOG(ERR, ARP_SENDER, "Could not read mac.\n");
        return 1;
    }
    return 0;
}

static int
read_ip(config_setting_t *arp_conf, const char *name, uint32_t *ip) {
    const char *ip_str;
    // get IP out of config file
    if (config_setting_lookup_string(arp_conf, name, &ip_str) == CONFIG_TRUE) {
        // parse IP (string to int)
        if (parse_ip(ip_str, ip) != 0) {
            RTE_LOG(ERR, ARP_SENDER, "Source IP has wrong format.\n");
            return 1;
        }
    } else {
        RTE_LOG(ERR, ARP_SENDER, "Could not read ip.\n");
        return 1;
    }
    return 0;
}

int
get_arp_sender(config_setting_t *arp_conf,
            struct app_config *appconfig, 
            struct arp_sender_t *arp_sender) {

    // SENDER
    unsigned sender_i;
    if (config_setting_lookup_int(arp_conf, CN_TX_ID, &sender_i) != CONFIG_TRUE) {
        RTE_LOG(ERR, ARP_SENDER, "Could not read %s.\n", CN_TX_ID);
        return 1;
    }

    if (sender_i > appconfig->nb_sender) {
        RTE_LOG(ERR, ARP_SENDER, "Sender index out of bounds. (%"PRIu32" of %"PRIu32" )\n", sender_i, appconfig->nb_sender);
        return 1;
    }
    arp_sender->tx = appconfig->sender[sender_i];
    arp_sender->tx->arp_sender = arp_sender;

    // DESTINATION MAC
    if (read_mac(arp_conf, CN_DST_MAC, &arp_sender->dst_mac) != 0) {
        RTE_LOG(ERR, ARP_SENDER, "Could not read %s.\n", CN_DST_MAC);
        return 1;
    }

    // SOURCE IP
    if (read_ip(arp_conf, CN_SRC_IP, &arp_sender->src_ip) != 0) {
        RTE_LOG(ERR, ARP_SENDER, "Could not read %s.\n", CN_SRC_IP);
        return 1;
    }

    // DESTINATION IP
    if (read_ip(arp_conf, CN_DST_IP, &arp_sender->dst_ip) != 0) {
        RTE_LOG(ERR, ARP_SENDER, "Could not read %s.\n", CN_DST_IP);
        return 1;
    }

    // TIMEOUT
    {
        int timeout;
        if (config_setting_lookup_int(arp_conf, CN_TIMEOUT, &timeout) != CONFIG_TRUE) {
            RTE_LOG(ERR, ARP_SENDER, "Could not read %s.\n", CN_TIMEOUT);
            return 1;
        }
        arp_sender->timeout = timeout;
    }

    arp_sender->sending = 0;
    arp_sender->pkt_pool = appconfig->pkt_pool;
    arp_sender->clone_pool = appconfig->clone_pool;

    return 0;
}
