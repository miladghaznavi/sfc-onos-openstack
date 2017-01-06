#include "mirrow.h"

#include "../config.h"
#include "../rxtx.h"
#include "../parse.h"
#include "../init.h"
#include "wrapping.h"

#include <stdlib.h>

#include <rte_malloc.h>
#include <rte_mbuf.h>
#include <rte_ethdev.h>
#include <rte_ether.h>
#include <rte_log.h>
#include <rte_byteorder.h>
#include <rte_cycles.h>

#define RTE_LOGTYPE_MIRROW RTE_LOGTYPE_USER1


void
mirrow_receive_pkt(void *arg, struct rte_mbuf **buffer, int nb_rx) {
	if (nb_rx == 0) return;

	uint64_t start = rte_get_tsc_cycles(), diff;

	struct mirrow_t *mirrow = (struct mirrow_t *) arg;
	mirrow->pkts_received += nb_rx;
	unsigned nb_tx = 0;

	size_t send_i = 0;
	for (unsigned pkt_i = 0; pkt_i < nb_rx; ++pkt_i) {

		struct ether_hdr *eth_old = rte_pktmbuf_mtod(buffer[pkt_i], struct ether_hdr *);
	
		/* forwarde packet only if it was send to our MAC. */
		if (!is_same_ether_addr(&mirrow->receive_port_mac, &eth_old->d_addr)) {
			mirrow->pkts_dropped += 1;
			continue;
		}
	
		struct rte_mbuf *m_clone = rte_pktmbuf_clone(buffer[pkt_i], mirrow->clone_pool);
		struct rte_mbuf *header = rte_pktmbuf_alloc(mirrow->pkt_pool);
	
		if (m_clone == NULL || header == NULL) {
			if (m_clone != NULL) rte_pktmbuf_free(m_clone);
			else if (header != NULL) rte_pktmbuf_free(m_clone);

			mirrow->pkts_failed += 1;
			continue;
		}
		header->data_len = sizeof(struct ether_addr) *2;
		header->pkt_len = sizeof(struct ether_addr) *2;

		struct ether_hdr *eth = rte_pktmbuf_mtod(m_clone, struct ether_hdr *);
		struct ether_hdr *eth_new = rte_pktmbuf_mtod(header, struct ether_hdr *);
		
		// swap MACs
		ether_addr_copy(&eth->s_addr, &eth_new->d_addr);
		ether_addr_copy(&mirrow->send_port_mac, &eth_new->s_addr);
	
		if (mirrow->decap_on_send) {
			wrapper_remove_data(m_clone);
		}
		if (mirrow->compress) {
			wrapper_compress(mirrow->pkt_pool, m_clone);
		}

		// remove ether addresses, make header the size of ethernet addresses
		rte_pktmbuf_adj(m_clone, sizeof(struct ether_addr) *2);

		// prepend new ether header:
		rte_pktmbuf_chain(header, m_clone);

		// send chained packet:		
		mirrow->send_buf[send_i] = header;
		send_i += 1;
	}


	int send = 0;//tx_put(mirrow->tx, mirrow->send_buf, send_i);
	while (send < send_i) {
		send += tx_put(mirrow->tx, (mirrow->send_buf + send), send_i - send);
		mirrow->nb_tries += 1;
	}
    diff = rte_get_tsc_cycles() - start;
    mirrow->time += diff;// * 1000.0 / rte_get_tsc_hz();
	mirrow->pkts_send += send;
	mirrow->nb_polls += 1;
	mirrow->nb_measurements += nb_rx;
}

void
log_mirrow(struct mirrow_t *m) {
	RTE_LOG(INFO, MIRROW, "------------- mirrow -------------\n");
	RTE_LOG(INFO, MIRROW, "| Out port:         %"PRIu16"\n", m->tx->port);
	RTE_LOG(INFO, MIRROW, "| send port MAC:    "FORMAT_MAC"\n", ARG_V_MAC(m->send_port_mac));
	RTE_LOG(INFO, MIRROW, "| receive port MAC: "FORMAT_MAC"\n", ARG_V_MAC(m->receive_port_mac));
	RTE_LOG(INFO, MIRROW, "| Packets received: %"PRIu64"\n", m->pkts_received);
	RTE_LOG(INFO, MIRROW, "| Packets send:     %"PRIu64"\n", m->pkts_send);
	RTE_LOG(INFO, MIRROW, "| Packets dropped:  %"PRIu64"\n", m->pkts_dropped);
	RTE_LOG(INFO, MIRROW, "| Packets failed:   %"PRIu64"\n", m->pkts_failed);
	if (m->nb_polls != 0)
		RTE_LOG(INFO, MIRROW, "| Tries:            %"PRIu64"\n", m->nb_tries/m->nb_polls);
	RTE_LOG(INFO, MIRROW, "| Time:             %f\n", m->time/m->nb_measurements);
	RTE_LOG(INFO, MIRROW, "-------------------------------------\n");
	m->nb_polls = 0;
	m->nb_tries = 0;
}

static int
read_mac(config_setting_t *m_conf, const char *name, struct ether_addr *mac) {
	const char * omac;
	if (config_setting_lookup_string(m_conf, name, &omac) == CONFIG_TRUE) {
		if (parse_mac(omac, mac) != 0) {
			RTE_LOG(ERR, MIRROW, "MAC has wrong format.\n");
			return 1;
		}
	} else {
		RTE_LOG(ERR, MIRROW, "Could not read mac.\n");
		return 1;
	}
	return 0;
}

int
get_mirrow(config_setting_t *m_conf,
			struct app_config *appconfig, 
			struct mirrow_t *mirrow) {

	// sender
	unsigned sender_i;
	if (config_setting_lookup_int(m_conf, CN_TX_ID, &sender_i) != CONFIG_TRUE) {
		RTE_LOG(ERR, MIRROW, "Could not read sender index.\n");
		return 1;
	}

	if (sender_i > appconfig->nb_sender) {
		RTE_LOG(ERR, MIRROW, "Sender index out of bounds. (%"PRIu32" of %"PRIu32" )\n", sender_i, appconfig->nb_sender);
		return 1;
	}
	mirrow->tx = appconfig->sender[sender_i];

	// receiver
	unsigned receiver_i;
	if (config_setting_lookup_int(m_conf, CN_RX_ID, &receiver_i) != CONFIG_TRUE) {
		RTE_LOG(ERR, MIRROW, "Could not read sender index.\n");
		return 1;
	}

	if (receiver_i > appconfig->nb_receiver) {
		RTE_LOG(ERR, MIRROW, "Receiver index out of bounds. (%"PRIu32" of %"PRIu32" )\n", receiver_i, appconfig->nb_receiver);
		return 1;
	}
	mirrow->rx = appconfig->receiver[receiver_i];

	// SOURCE MAC
	rte_eth_macaddr_get(mirrow->rx->in_port, &mirrow->receive_port_mac);
	rte_eth_macaddr_get(mirrow->tx->port, &mirrow->send_port_mac);

	// SHOULD DECAP ON SEND
	int should_decap = false;
	config_setting_lookup_bool(m_conf, CN_DECAP_ON_SEND, &should_decap);
	mirrow->decap_on_send = (bool) should_decap;

	// SHOULD COMPRESS ON SEND
	int should_compress = false;
	config_setting_lookup_bool(m_conf, CN_COMPRESS, &should_compress);
	mirrow->compress = (bool) should_compress;

	mirrow->pkts_received = 0;
	mirrow->pkts_send = 0;
	mirrow->pkts_dropped = 0;
	mirrow->pkts_failed = 0;
	mirrow->nb_polls = 0;
	mirrow->nb_tries = 0;
	mirrow->nb_mbuf = 0;
	mirrow->time = 0.0;
	mirrow->nb_measurements = 0.0;

	mirrow->send_buf = rte_malloc(NULL, sizeof(struct rte_mbuf*) * BURST_SIZE, 64);
	mirrow->pkt_pool = appconfig->pkt_pool;
	mirrow->clone_pool = appconfig->clone_pool;
	return 0;
}
