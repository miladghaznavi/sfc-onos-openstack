#ifndef RECEIVER_H_
#define RECEIVER_H_

#include <inttypes.h>
#include <libconfig.h>

#include <rte_mbuf.h>
#include <rte_ethdev.h>

#define BURST_SIZE 128

struct receiver_t {
    unsigned core_id;
    unsigned in_port;
    struct ether_addr mac;

    uint64_t pkts_received;
    uint64_t nb_polls;
    uint64_t nb_rec;

    unsigned nb_handler;
    void **args;
    void (**handler) (void *arg, struct rte_mbuf **m, int nb_rx);

    struct rte_mbuf **burst_buffer;
    uint64_t time;
    uint64_t nb_measurements;

};

void
log_receiver(struct receiver_t *receiver);

void
poll_receiver(struct receiver_t *receiver);

void
init_receiver(unsigned core_id, unsigned in_port,
            struct receiver_t *receiver);

#endif /* RECEIVER_H_ */
