#ifndef BENCH_SEND_H_
#define BENCH_SEND_H_

#include <inttypes.h>
#include <libconfig.h>

#include <rte_ether.h>

#include "types.h"

#define STOP_SEQ 0xFFFFFFFFFFFFFFFF
#define BURST_SIZE 32
#define CLOCKS_PER_U_SEC (CLOCKS_PER_SEC / 1000000)

struct bench_sender_t {
	/** Port on which we receive packets to replicate */
	unsigned output_port;
	unsigned core_id;

	/* Source and destination MAC address. */
	struct ether_addr src_mac;
	struct ether_addr dst_mac;

	/* Source and destination IP address. */
	uint32_t src_ip;
	uint32_t dst_ip;

	/* Destination UDP port. Source is set to 0. */
	uint16_t dst_udp_port;

	/** Memory pool for Packets etc */
	struct rte_mempool *cloned_pool;

	u_second_t last_tx;
	uint64_t pkts_send;

	uint64_t pkts_counter;
	uint64_t poll_counter;

	size_t cur_sequence;
	size_t nb_sequences;
	struct bench_sequence_t **sequences;

	struct rte_mbuf *prototype;

	struct rte_mbuf **send_buf;
};

struct bench_sequence_t {
	size_t nb_packets;
	size_t nb_packets_send;
	size_t pkt_per_sec;
	unsigned packet_size;
};

void
log_bench_sender(struct bench_sender_t *bs);

void
poll_bench_sender(struct bench_sender_t *bench_sender);

int
get_bench_sender(config_setting_t *bs_conf, 
				struct rte_mempool *cloned_pool, 
				struct bench_sender_t *bench_sender);

#endif /* BENCH_SEND_H_ */
