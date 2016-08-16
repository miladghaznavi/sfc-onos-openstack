#ifndef COUNTER_H_
#define COUNTER_H_

#include <inttypes.h>
#include <libconfig.h>
#include <stdbool.h>

#include <rte_mbuf.h>
#include <rte_ethdev.h>

struct app_config;

struct counter_t {
	struct transmit_t *tx;
	struct receiver_t *rx_register;
	struct receiver_t *rx_firewall;

	unsigned core_id;
	
	unsigned drop_at;
	bool encap_on_register;

	struct ether_addr send_src_mac;
	struct ether_addr dst_mac;

	struct rte_ring *ring;
	struct rte_mempool *pool;

	uint64_t pkts_received;
	uint64_t pkts_send;
};

void
counter_register_pkt(void *arg, struct rte_mbuf *m);

void
counter_firewall_pkt(void *arg, struct rte_mbuf *m);

void
log_counter(struct counter_t *counter);

void
poll_counter(struct counter_t *counter);

int
init_counter(config_setting_t *c_conf,
			struct app_config *appconfig, 
			struct counter_t *counter);


#endif /* COUNTER_H_ */
