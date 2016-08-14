#ifndef BENCH_SEND_H_
#define BENCH_SEND_H_

#include <inttypes.h>
#include <libconfig.h>

#include <rte_ether.h>

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

	uint64_t packet_interval;
	uint64_t tm_last_pkt_send;
	uint64_t pkts_send;
};

void
log_bench_sender(struct bench_sender_t * bs);

void
poll_bench_sender(struct bench_sender_t* bench_sender);

int
get_bench_sender(config_setting_t *bs_conf, 
				struct rte_mempool *cloned_pool, 
				struct bench_sender_t * bench_sender);

#endif /* BENCH_SEND_H_ */
