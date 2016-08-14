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

#define FALSE 0
#define TRUE  1
/**
 * The number of packets to poll from the ethernet device.
 */
#define RX_BURST_SIZE 32

/**
 * The number of packets to bundle for the ethernet device and send as burst.
 */
#define TX_BURST_SIZE 32

struct transmit_t *
tx_create_immediate(unsigned port, unsigned queue) {
  struct transmit_t * this = malloc(sizeof(struct transmit_t));

  this->ring       = NULL;
  this->nb_dropped = 0;
  this->immediate  = TRUE;
  this->port       = port;
  this->queue      = queue;

  return this;
}

struct transmit_t *
tx_create(unsigned size, unsigned port, unsigned queue) {
  struct transmit_t * this = malloc(sizeof(struct transmit_t));

  int r = rand();
  char ring_name[128];
  sprintf(ring_name, "tx_ring_%i", r);

  struct rte_ring * tx_ring =
    rte_ring_create(ring_name, size, SOCKET_ID_ANY, 0);

  if (tx_ring == NULL) {
    printf("Cannot create tx ring.\n");
    die();
  }

  double hz_tsc  = rte_get_tsc_hz();
  double us_p_s  = US_PER_S;
  double timeout = (rte_get_tsc_hz() / US_PER_S) / 100.0;

  printf("Timeout is set to %lu ticks\n", (unsigned long) timeout);

  this->immediate        = FALSE;
  this->ring             = tx_ring;
  this->last_transmit    = 0;
  this->nb_dropped       = 0;
  this->transmit_timeout = round(timeout);

  this->port  = port;
  this->queue = queue;

  return this;
}

int
tx_burst(struct transmit_t *this)
{
  struct rte_mbuf *pkt_buffer[TX_BURST_SIZE];

  this->last_transmit = rte_get_tsc_cycles();

  // Send until TX-ring is empty.
  uint16_t n = 0;
  do {
    n = rte_ring_sc_dequeue_burst(this->ring, (void **) pkt_buffer, TX_BURST_SIZE);
    if (n == 0) break;

    unsigned ret = rte_eth_tx_burst(this->port, this->queue, pkt_buffer, n);

    for (int i = 0; i < ret; i++) {
      //rte_pktmbuf_free(pkt_buffer[i]);
    }

    if (unlikely(ret < n)) {
      // Enqueue packets back into the TX-ring, if they could not be sent.
      do {
        tx_enqueue(this, pkt_buffer[ret]);
      } while (likely(++ret < n));

      // Stop with sending bursts since the TX-queue of the Ethernet device is
      // filled.
      // The packets can be sent later when the TX-queue has available space
      // again.
      if (unlikely(ret == 0)) {
        break;
      }
    }
  } while (likely(n > 0));

  return 0;
}

int
tx_put(struct transmit_t *this, struct rte_mbuf *m)
{
  if (this->immediate) {
    int send = rte_eth_tx_burst(this->port, this->queue, &m, 1);
    if (send != 1) {
      rte_pktmbuf_free(m);
    }
    return send;
  }

  tx_enqueue(this, m);
  unsigned size = rte_ring_count(this->ring);

  // Check Packet Count and last transmit time
  if (unlikely(size >= TX_BURST_SIZE ||
      rte_get_tsc_cycles() >= this->last_transmit + this->transmit_timeout)) {
    tx_burst(this);
  }

  return 0;
}
