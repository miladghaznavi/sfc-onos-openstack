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
#include <rte_ring.h>

struct transmit_t {
  struct rte_ring * ring;

  uint64_t last_transmit;
  uint64_t transmit_timeout;

  unsigned port;
  unsigned queue;
  unsigned immediate;

  unsigned long nb_dropped;
};

/**
 * Creates an normal-mode tx object.
 *
 * @param size
 *   Ring size
 * @param port
 *   Ouput port
 * @param queue
 *   Ouput port send queue
 */
struct transmit_t *
tx_create(unsigned size, unsigned port, unsigned queue);

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
 * Send a burst of packets on the output interface.
 */
int
tx_burst(struct transmit_t *this);

/**
 * Prepares a packet to be sent and enqueues them in the TX-queue.
 * If you just want to send packets, this is the method to use.
 *
 * @param m
 *   packet to send
 */
int
tx_put(struct transmit_t *this, struct rte_mbuf *m);

/**
 * Enqueues a packet to the TX-ring to be sent.
 *
 * Packets will be either transmitter or freed, when there is not enough space.
 *
 * @return
 *     0 if successful, EDQUOT if watermark is exceeded but object found
 *     enough remaining space or ENOBUFS if there is not enough space to store
 *     the packets.
 */
static inline int
tx_enqueue(struct transmit_t *this, struct rte_mbuf *m)
{
  // assert(rte_pktmbuf_read(m) == 1)

  if (unlikely(rte_ring_sp_enqueue(this->ring, m) == -ENOBUFS)) {
    rte_pktmbuf_free(m);
    this->nb_dropped++;
    printf("Dropped :(\n");
    return -ENOBUFS;
  }
  return 0;
}

#endif
