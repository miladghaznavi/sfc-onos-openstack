#ifndef BENCH_SEND_H_
#define BENCH_SEND_H_

#include <inttypes.h>
#include <libconfig.h>
#include <stdbool.h>

#include <rte_ether.h>

#include "types.h"

#define STOP_SEQ 0xFFFFFFFFFFFFFFFF
#define CLOCKS_PER_U_SEC (CLOCKS_PER_SEC / 1000000)
#define ETHER_TYPE ETHER_TYPE_IPv4
#define MAX_TRIES 0XFFFFFF

struct app_config;

struct bench_sender_t {
	/** Port on which we receive packets to replicate */
	struct transmit_t *tx;
	unsigned core_id;

	/* destination MAC addresses (ARRAY). */
	size_t nb_dst_macs;
	struct ether_addr *dst_macs;
	/* Specifeis if a outgoing packet should be compressed */
	bool *should_compress;

	/* Source and destination IP address. */
	uint32_t src_ip;
	uint32_t dst_ip;

	/* Destination UDP port. Source is set to 0. */
	uint16_t dst_udp_port;

	/** Memory pool for Packets etc */
	struct rte_mempool *pkt_pool;
	struct rte_mempool *clone_pool;

	uint64_t last_tx;
	uint64_t pkts_send;

	uint64_t pkts_counter;
	uint64_t should_pkts_counter;
	uint64_t poll_counter;

	size_t cur_sequence;
	size_t nb_sequences;
	struct bench_sequence_t **sequences;
	struct rte_mbuf ***send_buf;

	size_t nb_prototypes;
	struct rte_mbuf **prototypes;
	uint16_t prototype_ip_size; 
    double time;
    uint64_t nb_measurements;
};

struct bench_sequence_t {
	size_t nb_packets;
	size_t nb_packets_send;
	size_t pkt_per_sec;
	unsigned ip_size;
	unsigned send_end_packet;
};

void
log_bench_sender(struct bench_sender_t *bs);

void
poll_bench_sender(struct bench_sender_t *bench_sender);

int
get_bench_sender(config_setting_t *bs_conf, 
				struct app_config *appconfig, 
				struct bench_sender_t *bench_sender);

#endif /* BENCH_SEND_H_ */
