#ifndef RECEIVER_H_
#define RECEIVER_H_

#include <inttypes.h>
#include <libconfig.h>

#include <rte_mbuf.h>
#include <rte_ethdev.h>

struct receiver_t {
    unsigned core_id;
    unsigned in_port;

    uint64_t pkts_received;

    unsigned nb_handler;
    void **args;
    void (**handler) (void *arg, struct rte_mbuf *m);
};

void
log_receiver(struct receiver_t *receiver);

void
poll_receiver(struct receiver_t *receiver);

void
init_receiver(unsigned core_id, unsigned in_port,
            struct receiver_t *receiver);

#endif /* RECEIVER_H_ */
