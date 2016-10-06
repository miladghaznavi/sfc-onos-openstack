#ifndef RXTX_H_
#define RXTX_H_

#include <inttypes.h>

#include <rte_mbuf.h>

#include "components/arp_sender.h"

struct transmit_t {
    double hz;
	double last_transmit;

	unsigned port;
	unsigned queue;

	struct arp_sender_t *arp_sender;
	struct ether_addr send_port_mac;


};
/**
 * Creates an immediate-mode tx object,
 * which will send any packet given to tx_put immediately.
 *
 * @param port
 *   Ouput port
 * @param queue
 *   Ouput port send queue
 */
struct transmit_t *
tx_create_immediate(unsigned port, unsigned queue);

/**
 * Prepares a packet to be sent and enqueues them in the TX-queue.
 * If you just want to send packets, this is the method to use.
 *
 * @param m
 *   packet to send
 */
int
tx_put(struct transmit_t *this, struct rte_mbuf **m, int nb_tx);

#endif
