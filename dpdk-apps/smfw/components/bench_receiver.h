#ifndef BENCH_RECEIVER_H_
#define BENCH_RECEIVER_H_

#include <inttypes.h>
#include <libconfig.h>
#include <stdio.h>

#include <rte_ether.h>

#include "types.h"

struct app_config;

struct bench_statistic_t {
    uint64_t first_send;        //us
    uint64_t last_send;         //us
    uint64_t first_received;    //us
    uint64_t last_received;     //us
    uint64_t total_received;    //packets
    uint64_t sum_latency;       //us
};

struct bench_receiver_t {
    /** Port on which we receive packets to replicate */
    struct receiver_t *rx;

    unsigned udp_in_port;

    size_t cur_seq;
    size_t nb_names;
    char **sequence_names;
    char *file_name;
    FILE *log_fd;

    /*  
     * Fields for statistics
     */

    /* Number of bench packets received. */
    uint64_t pkts_received;

    /* Number of unknown packets received. */
    uint64_t pkts_skiped;

    struct bench_statistic_t statistics;

};

uint64_t
extract_timestamp(struct rte_mbuf *m, uint16_t udp_port, uint64_t **ptr_timestamps);

void
log_bench_receiver(struct bench_receiver_t *bench_receiver);

void
bench_receiver_receive_pkt(void *arg, struct rte_mbuf **buffer, int nb_rx);

int
get_bench_receiver(config_setting_t *br_conf, 
                struct app_config *appconfig, 
                struct bench_receiver_t *bench_receiver);

int
free_bench_receiver(struct bench_receiver_t *bench_receiver);

#endif /* BENCH_RECEIVER_H_ */
