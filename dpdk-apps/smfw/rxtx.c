#include "init.h"
#include "rxtx.h"

#include <assert.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdlib.h>
#include <math.h>

#include <rte_cycles.h>
#include <rte_ethdev.h>
#include <rte_mbuf.h>
#include <rte_ring.h>
#include <rte_ether.h>

#define RTE_LOGTYPE_TX RTE_LOGTYPE_USER1

struct transmit_t *
tx_create_immediate(unsigned port, unsigned queue) {

	struct transmit_t * this = malloc(sizeof(struct transmit_t));

	this->nb_dropped = 0;
	this->port       = port;
	this->queue      = queue;
	rte_eth_macaddr_get(this->port, &this->send_port_mac);

	return this;
}

int
tx_put(struct transmit_t *this, struct rte_mbuf **ms, int nb_tx) {

	// for (unsigned i = 0; i < nb_tx; ++i) {
	// 	rte_mbuf_sanity_check(ms[i], 1);
	// 	if (rte_mbuf_refcnt_read(ms[i]) < 1) RTE_LOG(WARNING, TX, "Ref count less than 1!\n");

	// 	struct ether_hdr *eth = rte_pktmbuf_mtod(ms[i], struct ether_hdr *);
	// 	ether_addr_copy(&this->send_port_mac, &eth->s_addr);
	// }
	return rte_eth_tx_burst(this->port, this->queue, ms, nb_tx);
}
