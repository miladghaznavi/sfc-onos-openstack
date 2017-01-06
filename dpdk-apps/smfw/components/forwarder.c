#include "forwarder.h"

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

#define RTE_LOGTYPE_FORWARDER RTE_LOGTYPE_USER1


void
forwarder_receive_pkt(void *arg, struct rte_mbuf **buffer, int nb_rx) {
	if (nb_rx == 0) return;

	uint64_t start = rte_get_tsc_cycles(), diff;

	struct forwarder_t *forwarder = (struct forwarder_t *) arg;
	forwarder->pkts_received += nb_rx;
	unsigned nb_tx = 0;

	size_t send_i = 0;
	for (unsigned pkt_i = 0; pkt_i < nb_rx; ++pkt_i) {

		struct ether_hdr *eth_old = rte_pktmbuf_mtod(buffer[pkt_i], struct ether_hdr *);
	
		/* forwarde packet only if it was send to our MAC. */
		if (!is_same_ether_addr(&forwarder->receive_port_mac, &eth_old->d_addr)) {
			RTE_LOG(INFO, FORWARDER, "Wrong d_MAC... "FORMAT_MAC"\n", ARG_V_MAC(eth_old->d_addr));
			forwarder->pkts_dropped += 1;
			continue;
		}
		struct rte_mbuf *m_clone_pro = rte_pktmbuf_clone(buffer[pkt_i], 
													forwarder->clone_pool);
		if (forwarder->decap_on_send)
			wrapper_remove_data(m_clone_pro);
		
		if (forwarder->compress)
			wrapper_compress(forwarder->pkt_pool, m_clone_pro);

		for (size_t mac_i = 0; mac_i < forwarder->nb_dst_macs; mac_i++) {
			/* Clone the mbuf. */
			struct rte_mbuf *m_clone = rte_pktmbuf_clone(m_clone_pro, 
														forwarder->clone_pool);
			struct rte_mbuf *header = rte_pktmbuf_clone(forwarder->eth_hdrs[mac_i],
														forwarder->clone_pool);
		
			if (m_clone == NULL || header == NULL) {
				if (m_clone != NULL) rte_pktmbuf_free(m_clone);
				else if (header != NULL) rte_pktmbuf_free(m_clone);
	
				forwarder->pkts_failed += 1;
				continue;
			}
	
			// remove ether header
			rte_pktmbuf_adj(m_clone, sizeof(struct ether_addr) *2);
	
			// prepend new ether header:
			rte_pktmbuf_chain(header, m_clone);
	
			// send chained packet:		
			forwarder->send_buf[send_i] = header;
			send_i += 1;
		}
		rte_pktmbuf_free(m_clone_pro);
	}


	int send = 0;//tx_put(forwarder->tx, forwarder->send_buf, send_i);
	while (send < send_i) {
		send += tx_put(forwarder->tx, (forwarder->send_buf + send), send_i - send);
		forwarder->nb_tries += 1;
	}
    diff = rte_get_tsc_cycles() - start;
    forwarder->time += diff;// * 1000.0 / rte_get_tsc_hz();
	forwarder->pkts_send += send;
	forwarder->nb_polls += 1;
	forwarder->nb_measurements += nb_rx;
}

void
log_forwarder(struct forwarder_t *f) {
	RTE_LOG(INFO, FORWARDER, "------------- Forwarder -------------\n");
	RTE_LOG(INFO, FORWARDER, "| Out port:         %"PRIu16"\n", f->tx->port);
	RTE_LOG(INFO, FORWARDER, "| send port MAC:    "FORMAT_MAC"\n", ARG_V_MAC(f->send_port_mac));
	RTE_LOG(INFO, FORWARDER, "| receive port MAC: "FORMAT_MAC"\n", ARG_V_MAC(f->receive_port_mac));
	for (size_t mac_i = 0; mac_i < f->nb_dst_macs; mac_i++)
		RTE_LOG(INFO, FORWARDER, "| dst MAC :          "FORMAT_MAC"\n", 
			ARG_V_MAC(f->dst_macs[mac_i]));
	RTE_LOG(INFO, FORWARDER, "| Packets received: %"PRIu64"\n", f->pkts_received);
	RTE_LOG(INFO, FORWARDER, "| Packets send:     %"PRIu64"\n", f->pkts_send);
	RTE_LOG(INFO, FORWARDER, "| Packets dropped:  %"PRIu64"\n", f->pkts_dropped);
	RTE_LOG(INFO, FORWARDER, "| Packets failed:   %"PRIu64"\n", f->pkts_failed);
	if (f->nb_polls != 0)
		RTE_LOG(INFO, FORWARDER, "| Tries:            %"PRIu64"\n", f->nb_tries/f->nb_polls);
	RTE_LOG(INFO, FORWARDER, "| Time:             %f\n", f->time/f->nb_measurements);
	RTE_LOG(INFO, FORWARDER, "-------------------------------------\n");
	f->nb_polls = 0;
	f->nb_tries = 0;
}

static int
read_mac(const char *mac_str, struct ether_addr *mac) {
	if (parse_mac(mac_str, mac) != 0) {
		RTE_LOG(ERR, FORWARDER, "Source MAC has wrong format.\n");
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
	config_setting_t *dst_mac_conf = config_setting_get_member(f_conf, CN_DST);
	if (dst_mac_conf == NULL) {
		RTE_LOG(INFO, FORWARDER, "No dst macs found.\n");
		return 1;
	}
	forwarder->nb_dst_macs = config_setting_length(dst_mac_conf);
	RTE_LOG(INFO, FORWARDER, "Got %ld dst MACs\n", forwarder->nb_dst_macs);
	forwarder->dst_macs = rte_malloc(NULL, sizeof(struct ether_addr)
										 * forwarder->nb_dst_macs, 64);
	forwarder->compress = rte_malloc(NULL, sizeof(bool)
										 * forwarder->nb_dst_macs, 64);

	for (size_t i = 0; i < forwarder->nb_dst_macs; ++i) {
		config_setting_t *d_cfg = config_setting_get_elem(dst_mac_conf, i);

		const char *mac_str;
		if (config_setting_lookup_string(d_cfg, CN_MAC, &mac_str) != CONFIG_TRUE) {
			RTE_LOG(ERR, FORWARDER, "error in config.\n");
			return 1; 
		}
		if (read_mac(mac_str, forwarder->dst_macs + i) != 0) {
			RTE_LOG(ERR, FORWARDER, "error in config.\n");
			return 1;
		}
		
	}
	// SHOULD COMPRESS ON SEND
	int should_compress = (int) false;
	config_setting_lookup_bool(f_conf, CN_COMPRESS, &should_compress);
	forwarder->compress = (bool) should_compress;

	// SHOULD DECAP ON SEND
	int should_decap = (int) false;
	config_setting_lookup_bool(f_conf, CN_DECAP_ON_SEND, &should_decap);
	forwarder->decap_on_send = (bool) should_decap;


	forwarder->pkts_received = 0;
	forwarder->pkts_send = 0;
	forwarder->pkts_dropped = 0;
	forwarder->pkts_failed = 0;
	forwarder->nb_polls = 0;
	forwarder->nb_tries = 0;
	forwarder->nb_mbuf = 0;
	forwarder->time = 0.0;
	forwarder->nb_measurements = 0.0;

	forwarder->send_buf = rte_malloc(NULL, sizeof(struct rte_mbuf*) * BURST_SIZE * forwarder->nb_dst_macs, 64);
	forwarder->pkt_pool = appconfig->pkt_pool;
	forwarder->clone_pool = appconfig->clone_pool;

	forwarder->eth_hdrs = rte_malloc(NULL, sizeof(void*) * forwarder->nb_dst_macs, 64);

	for (int mac_i=0; mac_i < forwarder->nb_dst_macs; mac_i++) {
		forwarder->eth_hdrs[mac_i] = rte_pktmbuf_alloc(forwarder->pkt_pool);
		if (forwarder->eth_hdrs[mac_i] == NULL) {
			RTE_LOG(ERR, FORWARDER, "Could not alloc pktmbuf.\n");
			return 1;
		}
		struct ether_hdr *eth = rte_pktmbuf_mtod(forwarder->eth_hdrs[mac_i], struct ether_hdr *);
	
		ether_addr_copy(&forwarder->dst_macs[mac_i], &eth->d_addr);
		ether_addr_copy(&forwarder->send_port_mac, &eth->s_addr);

		forwarder->eth_hdrs[mac_i]->data_len = sizeof(struct ether_addr) *2;
		forwarder->eth_hdrs[mac_i]->pkt_len = sizeof(struct ether_addr) *2;
		print_packet_hex(forwarder->eth_hdrs[mac_i]);
	}

	return 0;
}
