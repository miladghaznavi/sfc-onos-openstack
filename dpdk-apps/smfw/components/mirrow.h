#ifndef MIRROW_H_
#define MIRROW_H_

#include "receiver.h"

#include <inttypes.h>
#include <libconfig.h>
#include <stdbool.h>

#include <rte_mempool.h>
#include <rte_mbuf.h>
#include <rte_ethdev.h>

struct app_config;

struct mirrow_t {
	struct transmit_t *tx;
	struct receiver_t *rx;
	
	struct ether_addr receive_port_mac;
	struct ether_addr send_port_mac;

	bool decap_on_send;
	bool compress;

	//stats
	uint64_t pkts_received;
	uint64_t pkts_send;
	uint64_t pkts_dropped;
	uint64_t pkts_failed;
	uint64_t nb_polls;
	uint64_t nb_tries;

	//
	struct rte_mempool *pkt_pool;
	struct rte_mempool *clone_pool;
	struct rte_mbuf **send_buf;

    unsigned nb_mbuf;
    double time;
    uint64_t nb_measurements;
};

void
log_mirrow(struct mirrow_t *mirrow);

void
mirrow_receive_pkt(void *arg, struct rte_mbuf **buffer, int nb_rx);

int
get_mirrow(config_setting_t *f_conf,
			struct app_config *appconfig, 
			struct mirrow_t *mirrow);

#endif /* MIRROW_H_ */
