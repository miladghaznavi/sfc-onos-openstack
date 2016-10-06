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

#define PKT_HDR_SIZE (sizeof(struct ether_hdr) + sizeof(struct ipv4_hdr) + sizeof(struct udp_hdr))

#define RTE_LOGTYPE_BENCH_RECEIVER RTE_LOGTYPE_USER1


static int
open_log_file(struct bench_receiver_t *bench_receiver, int seq) {
	if (bench_receiver->nb_file_names <= seq) return 1;

	bench_receiver->cur_seq = seq;
	bench_receiver->cur_log_fd = fopen(bench_receiver->file_names[seq], "w");
	fputs("'seq nb';'send';'receive';\n", bench_receiver->cur_log_fd);

	return 0;
}

static int
open_next_log(struct bench_receiver_t *bench_receiver) {
	return open_log_file(bench_receiver, bench_receiver->cur_seq+1);
}

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
	uint64_t nb_timestamps = (rte_be_to_cpu_16(udp_hdr->dgram_len) - sizeof(struct udp_hdr)) / sizeof(uint64_t);

	*ptr_timestamps = msg_start;
	return nb_timestamps;
}

void
log_bench_receiver(struct bench_receiver_t *br) {
	RTE_LOG(INFO, BENCH_RECEIVER, "------------- Bench Receiver -------------\n");
	RTE_LOG(INFO, BENCH_RECEIVER, "| In port:                %"PRIu16"\n", br->rx->in_port);
	if (br->cur_seq < br->nb_file_names)
		RTE_LOG(INFO, BENCH_RECEIVER, "| Log file:               %s\n", br->file_names[br->cur_seq]);
	RTE_LOG(INFO, BENCH_RECEIVER, "| Packets received:       %"PRIu64"\n", br->pkts_received);
	RTE_LOG(INFO, BENCH_RECEIVER, "| Packets skiped:         %"PRIu64"\n", br->pkts_skiped);
	RTE_LOG(INFO, BENCH_RECEIVER, "| Avg. transmission time: %.2fms\n", 
										(float) us_to_ms(br->travel_tm) / (float)br->pkts_received);
	RTE_LOG(INFO, BENCH_RECEIVER, "------------------------------------------\n");
}

void
bench_receiver_receive_pkt(void *arg, struct rte_mbuf **buffer, int nb_rx) {
	if (nb_rx == 0) return;
	struct bench_receiver_t *bench_receiver = (struct bench_receiver_t *) arg;

	uint64_t time = (double) clock() / (double) CLOCKS_PER_U_SEC;

	for (unsigned index = 0; index < nb_rx; ++index) {
		uint64_t* timestamps;
		unsigned nb_timestamps = extract_timestamp(buffer[index], 
			bench_receiver->udp_in_port, &timestamps);
	
		if (nb_timestamps > 1) {
			uint64_t seq_nb = timestamps[0];
			uint64_t send_tm = timestamps[1];
		

			// Save values

			for (unsigned i = 0; i < nb_timestamps; ++i) {
				fprintf(bench_receiver->cur_log_fd, "%"PRIu64";", timestamps[i]);
			}
			fprintf(bench_receiver->cur_log_fd, "%"PRIu64";", time);
			fputs("\n", bench_receiver->cur_log_fd);

			bench_receiver->pkts_received += 1;
			bench_receiver->travel_tm += time - send_tm;
			if (seq_nb == STOP_SEQ && open_next_log(bench_receiver) != 0) {
                raise(SIGTERM);
			} 

		} else {
			bench_receiver->pkts_skiped += 1;
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

	// Log files
	config_setting_t *log_file_names = config_setting_lookup(br_conf, CN_LOG_FILES);
	if (log_file_names == NULL) {
		bench_receiver->nb_file_names = 0;
		RTE_LOG(INFO, BENCH_RECEIVER, "No file names.");
		return 0;
	}

	bench_receiver->nb_file_names = config_setting_length(log_file_names);
	bench_receiver->file_names = rte_malloc(NULL, sizeof(char*) * bench_receiver->nb_file_names, 64);

	for (size_t i = 0; i < bench_receiver->nb_file_names; i++) {
		const char *file_name = config_setting_get_string_elem(log_file_names, i);
		if (file_name == NULL) {
			RTE_LOG(ERR, BENCH_RECEIVER, "Could not read log file name.\n");
			return 1;
		}
		bench_receiver->file_names[i] = rte_malloc(NULL, (strlen(file_name) + 1) * sizeof(char), 64);
		strcpy(bench_receiver->file_names[i], file_name);

	}

	// init other fields:
	bench_receiver->pkts_received = 0;
	bench_receiver->travel_tm = 0;
	bench_receiver->pkts_skiped = 0;
	bench_receiver->cur_seq = 0;

	if (open_log_file(bench_receiver, 0) != 0) {
		RTE_LOG(ERR, BENCH_RECEIVER, "Could not open log file.\n");
		return 1;
	}

	log_bench_receiver(bench_receiver);
	return 0;
}

int
free_bench_receiver(struct bench_receiver_t *bench_receiver) {

	if (fclose(bench_receiver->cur_log_fd) != 0) {
		RTE_LOG(ERR, BENCH_RECEIVER, "Could not write to log file.\n");
	}
	rte_free(bench_receiver);
}
