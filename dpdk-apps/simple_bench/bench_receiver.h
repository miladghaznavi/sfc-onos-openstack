#ifndef BENCH_RECEIVER_H_
#define BENCH_RECEIVER_H_

#include <inttypes.h>
#include <libconfig.h>
#include <stdio.h>

#include <rte_ether.h>

#include "types.h"

struct bench_receiver_t {
    /** Port on which we receive packets to replicate */
    unsigned input_port;
    unsigned core_id;
    unsigned udp_in_port;

    size_t cur_seq;
    size_t nb_file_names;
    char **file_names;
    FILE *cur_log_fd;

    /*  
     * Fields for statistics
     */

    /* Number of bench packets received. */
    uint64_t pkts_received;

    /* Sum of time bench packets traveled. */
    u_second_t travel_tm;

    /* Number of unknown packets received. */
    uint64_t pkts_skiped;

};

uint64_t
extract_timestamp(struct rte_mbuf *m, uint16_t udp_port, uint64_t **ptr_timestamps);

void
log_bench_receiver(struct bench_receiver_t *bench_receiver);

void
poll_bench_receiver(struct bench_receiver_t *bench_receiver);

int
get_bench_receiver(config_setting_t *bs_conf, 
                struct bench_receiver_t *bench_receiver);


#endif /* BENCH_RECEIVER_H_ */
