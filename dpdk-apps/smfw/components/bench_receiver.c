#include "bench_receiver.h"

#include "bench_sender.h"
#include "../parse.h"
#include "../config.h"
#include "../init.h"
#include "receiver.h"

#include <stdlib.h>
#include <stdio.h>
#include <inttypes.h>
#include <time.h>
#include <sys/time.h>
#include <libconfig.h>
#include <signal.h>

#include <rte_malloc.h>
#include <rte_ethdev.h>
#include <rte_cycles.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_udp.h>
#include <rte_log.h>
#include <rte_mbuf.h>
#include <rte_branch_prediction.h>

#define PKT_HDR_SIZE (sizeof(struct ether_hdr) + sizeof(struct ipv4_hdr) + sizeof(struct udp_hdr))

#define RTE_LOGTYPE_BENCH_RECEIVER RTE_LOGTYPE_USER1

static void
write_log_file(struct bench_receiver_t *br) {
	size_t seq = br->cur_seq;
	if (seq >= br->nb_names) return;

	struct bench_statistic_t statistics = br->statistics;

	fputs(br->sequence_names[seq], br->log_fd);
	fprintf(br->log_fd, ";%f;", (float)br->statistics.sum_latency / (float)br->statistics.total_received);

	fprintf(br->log_fd, "%"PRIu64";", br->statistics.first_send);
	fprintf(br->log_fd, "%"PRIu64";", br->statistics.last_send);
	fprintf(br->log_fd, "%"PRIu64";", br->statistics.first_received);
	fprintf(br->log_fd, "%"PRIu64";", br->statistics.last_received);
	fprintf(br->log_fd, "%"PRIu64";", br->statistics.total_received);
	fputs("\n", br->log_fd);
	fflush(br->log_fd);

	// clear statistics
	memset(&br->statistics, 0, sizeof(struct bench_statistic_t));
}

uint64_t
extract_timestamp(struct rte_mbuf *m, uint16_t udp_port, uint64_t **ptr_timestamps) {

	uint64_t* msg_start;
	struct ether_hdr *eth_hdr;
	struct ipv4_hdr *ip_hdr;
	struct udp_hdr *udp_hdr;

	// VV     Test if packet is a bench packet   VVV

	eth_hdr = rte_pktmbuf_mtod(m, struct ether_hdr *);

	if (eth_hdr->ether_type != rte_cpu_to_be_16(ETHER_TYPE)) return 0;

	if (m->data_len < PKT_HDR_SIZE + sizeof(uint64_t)) return 0;

	ip_hdr = rte_pktmbuf_mtod_offset(m, struct ipv4_hdr *, sizeof(struct ether_hdr));

	if (ip_hdr->next_proto_id != IPPROTO_UDP) return 0;

	udp_hdr = rte_pktmbuf_mtod_offset(m, struct udp_hdr *, 
		sizeof(struct ether_hdr) + sizeof(struct ipv4_hdr));

	if (udp_hdr->dst_port != rte_cpu_to_be_16(udp_port)) return 0;
 
	// VV     Tests Passed!                      VVV

	msg_start = rte_pktmbuf_mtod_offset(m, uint64_t*, PKT_HDR_SIZE);
	uint64_t nb_timestamps = (rte_be_to_cpu_16(udp_hdr->dgram_len) - sizeof(struct udp_hdr)) / sizeof(uint64_t);

	*ptr_timestamps = msg_start;
	return nb_timestamps;
}

void
log_bench_receiver(struct bench_receiver_t *br) {
	RTE_LOG(INFO, BENCH_RECEIVER, "------------- Bench Receiver -------------\n");
	RTE_LOG(INFO, BENCH_RECEIVER, "| In port:                %"PRIu16"\n", br->rx->in_port);
	if (br->cur_seq < br->nb_names) {
		RTE_LOG(INFO, BENCH_RECEIVER, "| Log file:               %s\n", br->file_name);
		RTE_LOG(INFO, BENCH_RECEIVER, "| Sequence name:          %s\n", br->sequence_names[br->cur_seq]);
	}
	RTE_LOG(INFO, BENCH_RECEIVER, "| Packets received:       %"PRIu64"\n", br->pkts_received);
	RTE_LOG(INFO, BENCH_RECEIVER, "| Packets skiped:         %"PRIu64"\n", br->pkts_skiped);
	if (br->statistics.total_received != 0) {
		uint64_t send_time = br->statistics.last_send - br->statistics.first_send;
		RTE_LOG(INFO, BENCH_RECEIVER, "| PPS:                    %.1f\n", 
			((float) br->statistics.total_received / (float) send_time) * US_PER_S);
		RTE_LOG(INFO, BENCH_RECEIVER, "| Avg. transmission time: %.4fus\n", 
			(float)br->statistics.sum_latency / (float) br->statistics.total_received);
	}
	RTE_LOG(INFO, BENCH_RECEIVER, "------------------------------------------\n");
}

void
bench_receiver_receive_pkt(void *arg, struct rte_mbuf **buffer, int nb_rx) {
	if (nb_rx == 0) return;
	struct bench_receiver_t *br = (struct bench_receiver_t *) arg;

	uint64_t time = (double) clock() / (double) CLOCKS_PER_U_SEC;

	for (unsigned index = 0; index < nb_rx; ++index) {
		uint64_t* timestamps;
		unsigned nb_timestamps = extract_timestamp(buffer[index], 
			br->udp_in_port, &timestamps);
	
		if (nb_timestamps > 1) {
			uint64_t seq_nb = timestamps[0];
			uint64_t send_tm = timestamps[1];
			
			br->statistics.sum_latency += time - send_tm;
			
			br->statistics.total_received++;
			br->pkts_received++;

			if (unlikely(seq_nb == STOP_SEQ)) {
				write_log_file(br);
				br->cur_seq++;
				if (br->cur_seq >= br->nb_names) {
					RTE_LOG(ERR, BENCH_RECEIVER, "Last packet received! Exiting.\n");
					raise(SIGTERM);
				}
			} else if (unlikely(br->statistics.first_send == 0)) {
				br->statistics.first_send = send_tm;
				br->statistics.first_received = time;
			} else {
				br->statistics.last_send = send_tm;
				br->statistics.last_received = time;
			}

		} else {
			br->pkts_skiped += 1;
		}
	}
}

int
get_bench_receiver(config_setting_t *br_conf, 
                struct app_config *appconfig, 
                struct bench_receiver_t *bench_receiver) {
	
	// receiver
	unsigned receiver_i;
	if (config_setting_lookup_int(br_conf, CN_RX_ID, &receiver_i) != CONFIG_TRUE) {
		RTE_LOG(ERR, BENCH_RECEIVER, "Could not read sender index.\n");
		return 1;
	}

	if (receiver_i > appconfig->nb_receiver) {
		RTE_LOG(ERR, BENCH_RECEIVER, "Receiver index out of bounds. (%"PRIu32" of %"PRIu32" )\n", receiver_i, appconfig->nb_receiver);
		return 1;
	}
	bench_receiver->rx = appconfig->receiver[receiver_i];

	// UDP IN PORT
	if (config_setting_lookup_int(br_conf, CN_DST_UPD_PORT, &bench_receiver->udp_in_port) != CONFIG_TRUE) {
		RTE_LOG(ERR, BENCH_RECEIVER, "Could not read UDP ingress port number.\n");
		return 1;
	}

	// sequence Names
	config_setting_t *sequences_conf = config_setting_lookup(br_conf, CN_SEQUENCE);
	if (sequences_conf == NULL) {
		bench_receiver->nb_names = 0;
		RTE_LOG(INFO, BENCH_RECEIVER, "No sequence names.\n");
		return 1;
	}

	bench_receiver->nb_names = config_setting_length(sequences_conf);
	RTE_LOG(INFO, BENCH_RECEIVER, "Make space for %"PRIu64" names.\n", bench_receiver->nb_names);
	bench_receiver->sequence_names = rte_malloc(NULL, sizeof(char*) * bench_receiver->nb_names, 64);

	char sequence_name[90];
	for (size_t i = 0; i < bench_receiver->nb_names; i++) {
		config_setting_t *s_conf = config_setting_get_elem(sequences_conf, i);
		uint64_t pkt_per_sec;
		uint64_t nb_packets;
		uint64_t ip_size;

		// INTERVAL
		if (config_setting_lookup_int64(s_conf, CN_PKT_PER_SEC, (long long int *) &pkt_per_sec) != CONFIG_TRUE) {
			RTE_LOG(ERR, BENCH_RECEIVER, "Could not read %s.\n", CN_PKT_PER_SEC);
			return 1;
		}
	
		// PACKET NUMBER
		if (config_setting_lookup_int64(s_conf, CN_PACKET_NB, (long long int *) &nb_packets) != CONFIG_TRUE) {
			RTE_LOG(ERR, BENCH_RECEIVER, "Could not read %s.\n", CN_PACKET_NB);
			return 1;
		}
	
		// PACKET SIZE
		if (config_setting_lookup_int64(s_conf, CN_PACKET_SIZE, (long long int *) &ip_size) != CONFIG_TRUE) {
			RTE_LOG(ERR, BENCH_RECEIVER, "Could not read %s.\n", CN_PACKET_SIZE);
			return 1;
		}

		size_t size = sprintf(sequence_name, "%"PRIu64"B_%"PRIu64"nb_%"PRIu64"Hz", ip_size, nb_packets, pkt_per_sec);
		bench_receiver->sequence_names[i] = rte_malloc(NULL, size + 1, 64);
		strcpy(bench_receiver->sequence_names[i], sequence_name);
	}

	// file Name
	const char *file_name;
	if (config_setting_lookup_string(br_conf, CN_LOG_FILE, &file_name) != CONFIG_TRUE) {
		RTE_LOG(INFO, BENCH_RECEIVER, "No file name.");
		return 1;
	} else {
		bench_receiver->file_name = rte_malloc(NULL, (strlen(file_name) + 1) * sizeof(char), 64);
		strcpy(bench_receiver->file_name, file_name);
		bench_receiver->file_name[strlen(file_name)] = '\0';
	}

	// init other fields:
	bench_receiver->pkts_received = 0;
	bench_receiver->pkts_skiped = 0;
	bench_receiver->cur_seq = 0;

	bench_receiver->statistics.first_send = 0;
	bench_receiver->statistics.last_send = 0;
	bench_receiver->statistics.first_received = 0;
	bench_receiver->statistics.last_received = 0;
	bench_receiver->statistics.total_received = 0;
	bench_receiver->statistics.sum_latency = 0;

	bench_receiver->log_fd = fopen(bench_receiver->file_name, "w");
	fputs("name;Latency (us);First Send (us);Last Send (us);First Received (us);Last Received (us);Total Received;\n", bench_receiver->log_fd);

	log_bench_receiver(bench_receiver);
	return 0;
}

int
free_bench_receiver(struct bench_receiver_t *bench_receiver) {
	fclose(bench_receiver->log_fd);
	rte_free(bench_receiver);
}
