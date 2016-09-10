#include "bench_receiver.h"

#include "parse.h"
#include "config.h"

#include <stdlib.h>
#include <stdio.h>
#include <inttypes.h>
#include <time.h>
#include <sys/time.h>
#include <libconfig.h>

#include <rte_ethdev.h>
#include <rte_cycles.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_udp.h>
#include <rte_log.h>
#include <rte_mbuf.h>

#define BURST_SIZE 32
#define PKT_HDR_SIZE (sizeof(struct ether_hdr) + sizeof(struct ipv4_hdr) + sizeof(struct udp_hdr))

#define RTE_LOGTYPE_BENCH_RECEIVER RTE_LOGTYPE_USER4

uint64_t
extract_timestamp(struct rte_mbuf *m, uint16_t udp_port, uint64_t **ptr_timestamps) {

	uint64_t* msg_start;
	struct ether_hdr *eth_hdr;
	struct ipv4_hdr *ip_hdr;
	struct udp_hdr *udp_hdr;

	// VV     Test if packet is a bench packet   VVV

	eth_hdr = rte_pktmbuf_mtod(m, struct ether_hdr *);

	if (eth_hdr->ether_type != rte_cpu_to_be_16(ETHER_TYPE_IPv4)) return 0;

	if (m->data_len < PKT_HDR_SIZE + sizeof(uint64_t)) return 0;

	ip_hdr = rte_pktmbuf_mtod_offset(m, struct ipv4_hdr *, sizeof(struct ether_hdr));

	if (ip_hdr->next_proto_id != IPPROTO_UDP) return 0;

	udp_hdr = rte_pktmbuf_mtod_offset(m, struct udp_hdr *, 
		sizeof(struct ether_hdr) + sizeof(struct ipv4_hdr));

	if (udp_hdr->dst_port != rte_cpu_to_be_16(udp_port)) return 0;
 
	// VV     Tests Passed!                      VVV

	msg_start = rte_pktmbuf_mtod_offset(m, uint64_t*, PKT_HDR_SIZE);
	unsigned nb_timestamps =  (m->data_len - PKT_HDR_SIZE) / sizeof(uint64_t);

	*ptr_timestamps = msg_start;
	return nb_timestamps;
}

void
log_bench_receiver(struct bench_receiver_t *br) {
	RTE_LOG(INFO, BENCH_RECEIVER, "------------- Bench Receiver -------------\n");
	RTE_LOG(INFO, BENCH_RECEIVER, "| Core ID:                %"PRIu16"\n", br->core_id);
	RTE_LOG(INFO, BENCH_RECEIVER, "| In port:                %"PRIu16"\n", br->input_port);
	RTE_LOG(INFO, BENCH_RECEIVER, "| Log file:               %s\n", br->file_name);
	RTE_LOG(INFO, BENCH_RECEIVER, "| Packets received:       %"PRIu64"\n", br->pkts_received);
	RTE_LOG(INFO, BENCH_RECEIVER, "| Avg. transmission time: %.2fms\n", 
										(float) br->travel_tm / (float) (br->pkts_received * 1000));
	RTE_LOG(INFO, BENCH_RECEIVER, "------------------------------------------\n");
}

void
poll_bench_receiver(struct bench_receiver_t *bench_receiver) {
	const uint16_t port = bench_receiver->input_port;

	struct rte_mbuf *pkts_burst[BURST_SIZE];
	unsigned nb_rx = 0;

	struct timeval time_val;
	gettimeofday(&time_val, NULL);
	uint64_t time = (uint64_t) (time_val.tv_sec * 1000000 + time_val.tv_usec);

	nb_rx = rte_eth_rx_burst((uint8_t) port, 0,
					pkts_burst, BURST_SIZE);

	uint64_t sum_duration = 0;
	unsigned index;
	
	for (index = 0; index < nb_rx; ++index) {
		uint64_t* timestamps;
		unsigned nb_timestamps = extract_timestamp(pkts_burst[index], bench_receiver->udp_in_port, &timestamps);

		if (nb_timestamps > 0) {
			uint64_t first = *timestamps;
	
			for (unsigned i = 0; i < nb_timestamps; ++i) {
				fprintf(bench_receiver->log_fd, "%"PRIu64";", timestamps[i]);
			}

			fprintf(bench_receiver->log_fd, "%"PRIu64";", time);
			fputs("\n", bench_receiver->log_fd);

			bench_receiver->pkts_received += 1;
			bench_receiver->travel_tm += time - first;

		} else {
			bench_receiver->pkts_skiped += 1;
		}
		rte_pktmbuf_free(pkts_burst[index]);
	}
}

int
get_bench_receiver(config_setting_t *br_conf, 
				struct bench_receiver_t *bench_receiver) {

	// CORE ID
	if (config_setting_lookup_int(br_conf, CN_CORE_ID, &bench_receiver->core_id) != CONFIG_TRUE) {
		RTE_LOG(ERR, BENCH_RECEIVER, "Could not read core id.\n");
		return 1;
	}

	// IN PORT
	if (config_setting_lookup_int(br_conf, CN_IN_PORT, &bench_receiver->input_port) != CONFIG_TRUE) {
		RTE_LOG(ERR, BENCH_RECEIVER, "Could not read ingress port number.\n");
		return 1;
	}

	// UDP IN PORT
	if (config_setting_lookup_int(br_conf, CN_DST_UPD_PORT, &bench_receiver->udp_in_port) != CONFIG_TRUE) {
		RTE_LOG(ERR, BENCH_RECEIVER, "Could not read UDP ingress port number.\n");
		return 1;
	}

	// Log file
	const char *file_name;
	if (config_setting_lookup_string(br_conf, CN_LOG_FILE, &file_name) != CONFIG_TRUE) {
		RTE_LOG(ERR, BENCH_RECEIVER, "Could not read log file name.\n");
		return 1;
	}
	bench_receiver->file_name = malloc((strlen(file_name) + 1) * sizeof(char));
	strcpy(bench_receiver->file_name, file_name);
	bench_receiver->log_fd = fopen(bench_receiver->file_name, "w");

	// init other fields:
	bench_receiver->pkts_received = 0;
	bench_receiver->travel_tm = 0;
	bench_receiver->pkts_skiped = 0;

	log_bench_receiver(bench_receiver);
	return 0;
}

int
free_bench_receiver(struct bench_receiver_t *bench_receiver) {

	if (fclose(bench_receiver->log_fd) != 0) {
		RTE_LOG(ERR, BENCH_RECEIVER, "Could not write to log file.\n");
	}
	free(bench_receiver);
}
