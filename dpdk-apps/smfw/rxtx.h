/**
 * Functions which allow sending packets in bursts using DPDK-rings.
 *
 * @file rxtx.h
 * @author Matthias Drexler
 * @author Philipp Jeitner
 * @date 3 Dec 2015
 */

#ifndef RXTX_H_
#define RXTX_H_

#include <inttypes.h>

#include <rte_mbuf.h>

struct transmit_t {

	uint64_t last_transmit;
	uint64_t transmit_timeout;

	unsigned port;
	unsigned queue;
	unsigned immediate;

	struct ether_addr send_port_mac;

	uint64_t nb_dropped;
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
