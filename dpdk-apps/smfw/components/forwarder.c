#include "forwarder.h"

#include "../config.h"
#include "../rxtx.h"
#include "../parse.h"
#include "../init.h"
#include "wrapping.h"

#include <stdlib.h>

#include <rte_mbuf.h>
#include <rte_ethdev.h>
#include <rte_ether.h>
#include <rte_log.h>
#include <rte_byteorder.h>

#define RTE_LOGTYPE_FORWARDER RTE_LOGTYPE_USER1


void
forwarder_receive_pkt(void *arg, struct rte_mbuf **buffer, int nb_rx) {
	if (nb_rx == 0) return;
	struct forwarder_t *forwarder = (struct forwarder_t *) arg;
	forwarder->pkts_received += nb_rx;
	unsigned nb_tx = 0;

	for (unsigned pkt_i = 0; pkt_i < nb_rx; ++pkt_i) {
		clock_t start = clock(), diff;

		struct ether_hdr *eth_old = rte_pktmbuf_mtod(buffer[pkt_i], struct ether_hdr *);
	
		/* forwarde packet only if it was send to our MAC. */
		if (!is_same_ether_addr(&forwarder->receive_port_mac, &eth_old->d_addr)) {
			// RTE_LOG(INFO, FORWARDER, "Wrong d_MAC... "FORMAT_MAC"\n", ARG_V_MAC(eth_old->d_addr));
			forwarder->pkts_dropped += 1;
			continue;
		}
	
		/* Clone the mbuf. */
		struct rte_mbuf *m_clone = rte_pktmbuf_clone(buffer[pkt_i], forwarder->clone_pool);
		struct rte_mbuf *header = rte_pktmbuf_clone(forwarder->eth_hdr, forwarder->clone_pool);
		forwarder->nb_mbuf += 2;
	
		if (m_clone == NULL || header == NULL) {
			RTE_LOG(ERR, FORWARDER, "Could not clone packet! Mempool empty?\n");
			forwarder->pkts_dropped += 1;
			forwarder->nb_mbuf -= 2;
			continue;
		}

		// RTE_LOG(INFO, FORWARDER, "Old packet:\n");
		// print_packet_hex(m_clone);

		if (forwarder->decap_on_send) {
			wrapper_remove_data(m_clone);
		}

		// remove ether header
		rte_pktmbuf_adj(m_clone, sizeof(struct ether_hdr));

		// prepend new ether header:
		rte_pktmbuf_chain(header, m_clone);

		// RTE_LOG(INFO, FORWARDER, "New packet:\n");
		// print_packet_hex(header);

		// send chained packet:
		int send = 0;
		while (send == 0) {
			send = tx_put(forwarder->tx, &header, 1);
		}
		forwarder->pkts_send += send;
		forwarder->nb_mbuf -= 2;

		diff = clock() - start;
		forwarder->time += diff * 1000.0 / CLOCKS_PER_SEC;
		forwarder->nb_measurements += 1;
	}
}

void
log_forwarder(struct forwarder_t *f) {
	RTE_LOG(INFO, FORWARDER, "------------- Forwarder -------------\n");
	RTE_LOG(INFO, FORWARDER, "| Out port:         %"PRIu16"\n", f->tx->port);
	RTE_LOG(INFO, FORWARDER, "| send port MAC:    "FORMAT_MAC"\n", ARG_V_MAC(f->send_port_mac));
	RTE_LOG(INFO, FORWARDER, "| receive port MAC: "FORMAT_MAC"\n", ARG_V_MAC(f->receive_port_mac));
	RTE_LOG(INFO, FORWARDER, "| dst MAC:          "FORMAT_MAC"\n", ARG_V_MAC(f->dst_mac));
	RTE_LOG(INFO, FORWARDER, "| Packets received: %"PRIu64"\n", f->pkts_received);
	RTE_LOG(INFO, FORWARDER, "| Packets send:     %"PRIu64"\n", f->pkts_send);
	RTE_LOG(INFO, FORWARDER, "| Packets dropped:  %"PRIu64"\n", f->pkts_dropped);
	RTE_LOG(INFO, FORWARDER, "| Time:             %f\n", f->time/f->nb_measurements);
	RTE_LOG(INFO, FORWARDER, "-------------------------------------\n");
}

static int
read_mac(config_setting_t *f_conf, const char *name, struct ether_addr *mac) {
	const char * omac;
	if (config_setting_lookup_string(f_conf, name, &omac) == CONFIG_TRUE) {
		if (parse_mac(omac, mac) != 0) {
			RTE_LOG(ERR, FORWARDER, "MAC has wrong format.\n");
			return 1;
		}
	} else {
		RTE_LOG(ERR, FORWARDER, "Could not read mac.\n");
		return 1;
	}
	return 0;
}

int
get_forwarder(config_setting_t *f_conf,
			struct app_config *appconfig, 
			struct forwarder_t *forwarder) {

	// sender
	unsigned sender_i;
	if (config_setting_lookup_int(f_conf, CN_TX_ID, &sender_i) != CONFIG_TRUE) {
		RTE_LOG(ERR, FORWARDER, "Could not read sender index.\n");
		return 1;
	}

	if (sender_i > appconfig->nb_sender) {
		RTE_LOG(ERR, FORWARDER, "Sender index out of bounds. (%"PRIu32" of %"PRIu32" )\n", sender_i, appconfig->nb_sender);
		return 1;
	}
	forwarder->tx = appconfig->sender[sender_i];

	// receiver
	unsigned receiver_i;
	if (config_setting_lookup_int(f_conf, CN_RX_ID, &receiver_i) != CONFIG_TRUE) {
		RTE_LOG(ERR, FORWARDER, "Could not read sender index.\n");
		return 1;
	}

	if (receiver_i > appconfig->nb_receiver) {
		RTE_LOG(ERR, FORWARDER, "Receiver index out of bounds. (%"PRIu32" of %"PRIu32" )\n", receiver_i, appconfig->nb_receiver);
		return 1;
	}
	forwarder->rx = appconfig->receiver[receiver_i];

	// SOURCE MAC
	rte_eth_macaddr_get(forwarder->rx->in_port, &forwarder->receive_port_mac);
	rte_eth_macaddr_get(forwarder->tx->port, &forwarder->send_port_mac);

	//DESTINATION MAC
	if (read_mac(f_conf, CN_DST_MAC, &forwarder->dst_mac) != 0) {
		RTE_LOG(ERR, FORWARDER, "Could not read destination MAC.\n");
		return 1;
	}

	// SHOULD DECAP ON SEND
	int should_decap;
	if (config_setting_lookup_bool(f_conf, CN_DECAP_ON_SEND, &should_decap) != CONFIG_TRUE) {
		RTE_LOG(ERR, FORWARDER, "Could not read %s.\n", CN_DECAP_ON_SEND);
		return 1;
	}
	forwarder->decap_on_send = (bool) should_decap;

	forwarder->pkts_received = 0;
	forwarder->pkts_send = 0;
	forwarder->pkts_dropped = 0;
	forwarder->nb_mbuf = 0;
	forwarder->time = 0.0;
	forwarder->nb_measurements = 0.0;

	forwarder->pkt_pool = appconfig->pkt_pool;
	forwarder->clone_pool = appconfig->clone_pool;

	forwarder->eth_hdr = rte_pktmbuf_alloc(forwarder->pkt_pool);
	if (forwarder->eth_hdr == NULL) {
		RTE_LOG(ERR, FORWARDER, "Could not alloc pktmbuf.\n");
		return 1;
	}
	forwarder->eth_hdr->data_len = sizeof(struct ether_hdr);

	struct ether_hdr *eth = rte_pktmbuf_mtod(forwarder->eth_hdr, struct ether_hdr *);

	eth->ether_type = rte_be_to_cpu_16(ETHER_TYPE_IPv4);
	ether_addr_copy(&forwarder->send_port_mac, &eth->s_addr);
	ether_addr_copy(&forwarder->dst_mac, &eth->d_addr);
	print_packet_hex(forwarder->eth_hdr);
	return 0;
}
