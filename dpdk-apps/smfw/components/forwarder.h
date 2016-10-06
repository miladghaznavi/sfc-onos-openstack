#ifndef FORWARDER_H_
#define FORWARDER_H_

#include "receiver.h"

#include <inttypes.h>
#include <libconfig.h>
#include <stdbool.h>

#include <rte_mempool.h>
#include <rte_mbuf.h>
#include <rte_ethdev.h>

struct app_config;

struct forwarder_t {
	struct transmit_t *tx;
	struct receiver_t *rx;

	unsigned out_mac;

	struct ether_addr receive_port_mac;
	struct ether_addr send_port_mac;
	struct ether_addr dst_mac;

	bool decap_on_send;

	uint64_t pkts_received;
	uint64_t pkts_send;
	uint64_t pkts_dropped;
	uint64_t pkts_failed;

	struct rte_mbuf *eth_hdr;
	struct rte_mempool *pkt_pool;
	struct rte_mempool *clone_pool;
	struct rte_mbuf **send_buf;

    unsigned nb_mbuf;
    double time;
    uint64_t nb_measurements;
};

void
log_forwarder(struct forwarder_t *forwarder);

void
forwarder_receive_pkt(void *arg, struct rte_mbuf **buffer, int nb_rx);

int
get_forwarder(config_setting_t *f_conf,
			struct app_config *appconfig, 
			struct forwarder_t *forwarder);

#endif /* FORWARDER_H_ */
