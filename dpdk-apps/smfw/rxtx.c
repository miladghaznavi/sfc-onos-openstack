#include "init.h"
#include "rxtx.h"
#include "parse.h"

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
#include <rte_branch_prediction.h>

#define RTE_LOGTYPE_TX RTE_LOGTYPE_USER1

struct transmit_t *
tx_create_immediate(unsigned port, unsigned queue) {

	struct transmit_t * this = malloc(sizeof(struct transmit_t));

	this->hz = rte_get_timer_hz();
	this->last_transmit = 0;
	this->port = port;
	this->queue = queue;
	this->arp_sender = NULL;
	rte_eth_macaddr_get(this->port, &this->send_port_mac);

	return this;
}

inline int
tx_put(struct transmit_t *this, struct rte_mbuf **ms, int nb_tx) {
	// double now = cycles_to_ns(rte_get_timer_cycles(), this->hz);

	// /* send arp packet if timeout is reached */
	// if (unlikely(this->arp_sender != NULL &&
	// 	now - this->last_transmit > this->arp_sender->timeout * NS_PER_S)) {
	// 	poll_arp_sender(this->arp_sender);
	// }
	// this->last_transmit = now;
	return rte_eth_tx_burst(this->port, this->queue, ms, nb_tx);
}
