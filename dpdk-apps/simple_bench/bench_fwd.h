#ifndef BENCH_FWD_H_
#define BENCH_FWD_H_

#include <inttypes.h>
#include <libconfig.h>

#include <rte_ether.h>

#define MAX_PKT_BURST 32

struct bench_forwarder_t {
    /** Port on which we receive packets to replicate */
    unsigned in_port;
    unsigned out_port;
    unsigned core_id;

    struct ether_addr receive_mac;
    struct ether_addr dst_mac;

    uint64_t pkts_send;
    uint64_t pkts_received;
    uint64_t pkts_dropped;
    uint64_t travel_tm;

    struct rte_mempool *cloned_pool;

    struct transmit_t *tx;
    uint64_t last_burst;
};

void
log_bench_forwarder(struct bench_forwarder_t *bench_forwarder);

void
poll_bench_forwarder(struct bench_forwarder_t *bench_forwarder);

int
get_bench_forwarder(config_setting_t *bs_conf, 
                struct rte_mempool *cloned_pool, 
                struct bench_forwarder_t *bench_forwarder);

#endif /* BENCH_FWD_H_ */
