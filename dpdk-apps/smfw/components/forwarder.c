#include "forwarder.h"

#include "../config.h"
#include "../rxtx.h"
#include "../parse.h"
#include "../init.h"

#include <stdlib.h>

#include <rte_mbuf.h>
#include <rte_ethdev.h>
#include <rte_ether.h>
#include <rte_log.h>

#define RTE_LOGTYPE_FORWARDER RTE_LOGTYPE_USER1


void
forwarder_receive_pkt(void *arg, struct rte_mbuf **buffer, int nb_rx) {
	struct forwarder_t *forwarder = (struct forwarder_t *) arg;
	forwarder->pkts_received += nb_rx;

	struct rte_mbuf *bulk[nb_rx];
	unsigned nb_tx = 0;

	for (unsigned pkt_i = 0; pkt_i < nb_rx; ++pkt_i) {
		struct ether_hdr *eth_old = rte_pktmbuf_mtod(buffer[pkt_i], struct ether_hdr *);
	
		/* forwarde packet only if it was send to our MAC. */
		if (!is_same_ether_addr(&forwarder->receive_port_mac, &eth_old->d_addr)) {
			forwarder->pkts_dropped += 1;
			continue;
		}
	
		/* Clone the mbuf. */
		struct rte_mbuf *m_clone = rte_pktmbuf_clone(buffer[pkt_i], forwarder->pool);
	
		if (m_clone == NULL) {
			RTE_LOG(ERR, FORWARDER, "Could not clone packet! Mempool empty?\n");
			forwarder->pkts_dropped += 1;
			continue;
		}
	
		struct ether_hdr *eth = rte_pktmbuf_mtod(m_clone, struct ether_hdr *);
	
		ether_addr_copy(&forwarder->send_port_mac, &eth->s_addr);
		ether_addr_copy(&forwarder->dst_mac, &eth->d_addr);

		bulk[nb_tx] = m_clone;
		nb_tx += 1;
	}
	int send = tx_put(forwarder->tx, bulk, nb_tx);
	forwarder->pkts_send += send;
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

	forwarder->pkts_received = 0;
	forwarder->pkts_send = 0;
	forwarder->pkts_dropped = 0;
	forwarder->pool = appconfig->mempool;

	return 0;
}
