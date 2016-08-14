#include "bench_fwd.h"

#include "parse.h"
#include "config.h"
#include "rxtx.h"
#include "bench_receiver.h"

#include <stdlib.h>
#include <time.h>
#include <sys/time.h>

#include <rte_mbuf.h>
#include <rte_ethdev.h>
#include <rte_ether.h>
#include <rte_log.h>

#define RTE_LOGTYPE_BENCH_FWD RTE_LOGTYPE_USER4


void
log_bench_forwarder(struct bench_forwarder_t *bf) {
	RTE_LOG(INFO, BENCH_FWD, "------------- Bench Forwarder -------------\n");
	RTE_LOG(INFO, BENCH_FWD, "| Core ID:                %"PRIu16"\n", bf->core_id);
	RTE_LOG(INFO, BENCH_FWD, "| In port:                %"PRIu16"\n", bf->in_port);
	RTE_LOG(INFO, BENCH_FWD, "| Out port:               %"PRIu16"\n", bf->out_port);
	RTE_LOG(INFO, BENCH_FWD, "| Port MAC:               "FORMAT_MAC"\n", ARG_V_MAC(bf->receive_mac));
	RTE_LOG(INFO, BENCH_FWD, "| Packets received:       %"PRIu64"\n", bf->pkts_received);
	RTE_LOG(INFO, BENCH_FWD, "| Packets send:           %"PRIu64"\n", bf->pkts_send);
	RTE_LOG(INFO, BENCH_FWD, "| Packets dropped:        %"PRIu64"\n", bf->pkts_dropped);
	RTE_LOG(INFO, BENCH_FWD, "| Avg. transmission time: %.2fms\n", 
								(float) bf->travel_tm / (float) (bf->pkts_send * 1000));
	RTE_LOG(INFO, BENCH_FWD, "-------------------------------------------\n");
}

static void
forward(struct bench_forwarder_t *bf, struct rte_mbuf *m)
{
	struct ether_hdr *eth = rte_pktmbuf_mtod(m, struct ether_hdr *);

	ether_addr_copy(&bf->receive_mac, &eth->s_addr);
	ether_addr_copy(&bf->dst_mac, &eth->d_addr);

	int send = tx_put(bf->tx, m);
	bf->pkts_send += send;
}

void
poll_bench_forwarder(struct bench_forwarder_t *bf) {

    struct rte_mbuf *pkts_burst[MAX_PKT_BURST];

	unsigned nb_rx = rte_eth_rx_burst(bf->in_port, 0, pkts_burst, MAX_PKT_BURST);
	bf->pkts_received += nb_rx;

	struct timeval time_val;
	gettimeofday(&time_val, NULL);
	uint64_t time = (uint64_t) (time_val.tv_sec * 1000000 + time_val.tv_usec);

	struct rte_mbuf *m;


	for (unsigned j = 0; j < nb_rx; j++) {
		m = pkts_burst[j];

		struct ether_hdr *eth_hdr = rte_pktmbuf_mtod(m, struct ether_hdr *);
		if (is_same_ether_addr(&eth_hdr->d_addr, &bf->receive_mac)) {

			uint64_t* timestamps;
			unsigned nb_timestamps = extract_timestamp(m, 666, &timestamps);
	
			if (nb_timestamps > 0) {
				uint64_t first = *timestamps;
	
				bf->travel_tm += time - first;
				uint64_t *m_tm = (uint64_t*) rte_pktmbuf_append(m, sizeof(uint64_t));
				if (m_tm != NULL) {
					*m_tm = time;
				}
				rte_prefetch0(rte_pktmbuf_mtod(m, void *));
				forward(bf, m);
			} else {
				rte_pktmbuf_free(m);
				bf->pkts_dropped += 1;
			}
		} else {
			rte_pktmbuf_free(m);
			bf->pkts_dropped += 1;
		}
	}
}

static int
read_mac(config_setting_t *bf_conf, const char *name, struct ether_addr *mac) {
	const char * omac;
	if (config_setting_lookup_string(bf_conf, name, &omac) == CONFIG_TRUE) {
		if (parse_mac(omac, mac) != 0) {
			RTE_LOG(ERR, BENCH_FWD, "Source MAC has wrong format.\n");
			return 1;
		}
	} else {
		RTE_LOG(ERR, BENCH_FWD, "Could not read mac.\n");
		return 1;
	}
	return 0;
}

int
get_bench_forwarder(config_setting_t *bf_conf, 
                struct rte_mempool *cloned_pool, 
				struct bench_forwarder_t *bench_forwarder) {
	// CORE ID
	if (config_setting_lookup_int(bf_conf, CN_CORE_ID, &bench_forwarder->core_id) != CONFIG_TRUE) {
		RTE_LOG(ERR, BENCH_FWD, "Could not read core id.\n");
		return 1;
	}

	// OUT PORT
	if (config_setting_lookup_int(bf_conf, CN_OUT_PORT, &bench_forwarder->out_port) != CONFIG_TRUE) {
		RTE_LOG(ERR, BENCH_FWD, "Could not read outgiong port number.\n");
		return 1;
	}
	// IN PORT
	if (config_setting_lookup_int(bf_conf, CN_IN_PORT, &bench_forwarder->in_port) != CONFIG_TRUE) {
		RTE_LOG(ERR, BENCH_FWD, "Could not read ingress port number.\n");
		return 1;
	}

	// SOURCE MAC
	rte_eth_macaddr_get(bench_forwarder->in_port, &bench_forwarder->receive_mac);

	//DESTINATION MAC
	if (read_mac(bf_conf, CN_DST_MAC, &bench_forwarder->dst_mac) != 0) {
		RTE_LOG(ERR, BENCH_FWD, "Could not read dastination MAC.\n");
		return 1;
	}

	bench_forwarder->tx = tx_create_immediate(bench_forwarder->out_port, 0);
	bench_forwarder->pkts_received = 0;
	bench_forwarder->pkts_send = 0;
	bench_forwarder->pkts_dropped = 0;
	bench_forwarder->travel_tm = 0;
	bench_forwarder->last_burst = 0;

	bench_forwarder->cloned_pool = cloned_pool;

	log_bench_forwarder(bench_forwarder);

	return 0;
}
