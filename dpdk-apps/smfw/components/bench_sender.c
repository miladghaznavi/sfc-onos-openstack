/*
 *
 */

#include "bench_sender.h"

#include "../parse.h"
#include "../config.h"
#include "../init.h"
#include "receiver.h"

#include <stdlib.h>
#include <inttypes.h>
#include <time.h>
#include <sys/time.h>
#include <libconfig.h>

#include <rte_malloc.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_udp.h>
#include <rte_ethdev.h>
#include <rte_cycles.h>

#define RTE_LOGTYPE_BENCH_SENDER RTE_LOGTYPE_USER3

#define SOURCE_UDP_PORT 0
#define BUFF_TIME_B4_SWITCH 1000 //ms
#define BUFF_TIME_AFTR_SWITCH 1000 //ms

static struct rte_mbuf *
gen_packet(struct bench_sender_t *bench_sender, char *msg, uint32_t msg_size) {
	uint32_t pkt_size;
	struct ether_hdr *eth_hdr;
	struct ipv4_hdr *ip_hdr;
	struct udp_hdr *udp_hdr;
	char*msg_start;
	struct bench_sequence_t *sequence;

	sequence = bench_sender->sequences[bench_sender->cur_sequence];

	pkt_size = sizeof(struct ether_hdr) + sequence->packet_size;
	
	struct rte_mbuf *m = rte_pktmbuf_alloc(bench_sender->pkt_pool);
	if (m == NULL || m->buf_len <= pkt_size) {
		RTE_LOG(ERR, BENCH_SENDER, "mbuf alloc failed!\n");
		die();
	}

	m->data_len = pkt_size;
	m->pkt_len = pkt_size;

	eth_hdr = rte_pktmbuf_mtod(m, struct ether_hdr *);
	ether_addr_copy(&bench_sender->src_mac, &eth_hdr->s_addr);
	ether_addr_copy(&bench_sender->dst_mac, &eth_hdr->d_addr);
	eth_hdr->ether_type = rte_cpu_to_be_16(ETHER_TYPE_IPv4);

	ip_hdr = rte_pktmbuf_mtod_offset(m, struct ipv4_hdr *, sizeof(struct ether_hdr));
	ip_hdr->version_ihl = 0x45;
	ip_hdr->time_to_live = 64;
	ip_hdr->src_addr = rte_cpu_to_be_32(bench_sender->src_ip);
	ip_hdr->dst_addr = rte_cpu_to_be_32(bench_sender->dst_ip);
	ip_hdr->next_proto_id = IPPROTO_UDP;
	ip_hdr->total_length = rte_cpu_to_be_16(pkt_size - sizeof(struct ether_hdr));

	ip_hdr->hdr_checksum  = rte_ipv4_cksum(ip_hdr);

	udp_hdr = rte_pktmbuf_mtod_offset(m, struct udp_hdr *, 
		sizeof(struct ether_hdr) + sizeof(struct ipv4_hdr));
	udp_hdr->src_port = SOURCE_UDP_PORT;
	udp_hdr->dst_port = rte_cpu_to_be_16(bench_sender->dst_udp_port);
	udp_hdr->dgram_len = rte_cpu_to_be_16(msg_size + sizeof(struct udp_hdr));
	msg_start = rte_pktmbuf_mtod_offset(m, char*, sizeof(struct ether_hdr) 
					+ sizeof(struct ipv4_hdr) + sizeof(struct udp_hdr));

	if (msg != NULL)
		memcpy(msg_start, msg, msg_size);

	return m;
}

// static struct rte_mbuf *
// get_packet(struct bench_sender_t *bench_sender, char *msg, uint32_t msg_size) {
// 	struct rte_mbuf * proto = bench_sender->prototype;

// }

void
poll_bench_sender(struct bench_sender_t *bench_sender) {
	if (bench_sender->cur_sequence >= bench_sender->nb_sequences) return;

	// get time and current sequence config
	clock_t c_time = clock();
	u_second_t time = (double) c_time / (double) CLOCKS_PER_U_SEC;
	struct bench_sequence_t *sequence = bench_sender->sequences[bench_sender->cur_sequence];

	// check if we have to wait between sequences
	if (sequence->nb_packets_send >= sequence->nb_packets) {

		// sequence N -- NOW --- END-SEQ-PCKT ----- sequence N+1 (or end...)
		if (time - bench_sender->last_tx > ms_to_us(BUFF_TIME_B4_SWITCH) && 
							sequence->nb_packets_send <= sequence->nb_packets) {

			uint64_t msg[2];
			msg[0] = STOP_SEQ;
			msg[1] = time;

			struct rte_mbuf *m = gen_packet(bench_sender, (char *) msg, sizeof(uint64_t) *2);
			
			int send = 0;
			while (send == 0) {
				send = rte_eth_tx_burst(bench_sender->output_port, 0, &m, 1);
			}
			sequence->nb_packets_send++;
		} else if (time - bench_sender->last_tx > ms_to_us(BUFF_TIME_B4_SWITCH) + ms_to_us(BUFF_TIME_AFTR_SWITCH)) {
		// sequence N ----- (END-SEQ-PCKT) ------ NOW ----- sequence N+1 (or end...)
			bench_sender->cur_sequence++;
			bench_sender->last_tx = time;

		} 
		return;
	}

	// determine the number of packets to send
	uint64_t send_count = ((time - bench_sender->last_tx) * sequence->pkt_per_sec) / ms_to_us(s_to_ms(1));

	// check that packet count is valid
	if (send_count == 0) return;
	else if (send_count > BURST_SIZE) send_count = BURST_SIZE;

	// generate the packets
	uint64_t nb_packets_send = sequence->nb_packets_send;
	for (size_t i = 0; i < send_count; ++i) {
		if (nb_packets_send >= sequence->nb_packets) {
			send_count = i;
			break;
		}

		uint64_t msg[2];
		msg[0] = nb_packets_send;
		msg[1] = time;

		bench_sender->send_buf[i] = gen_packet(bench_sender, (char *) msg, sizeof(uint64_t) *2);
		nb_packets_send++;
	}

	// send the generated packets
	int send = rte_eth_tx_burst(bench_sender->output_port, 0, bench_sender->send_buf, send_count);
	sequence->nb_packets_send += send;
	bench_sender->pkts_send += send;

	// stats
	bench_sender->pkts_counter += send;
	bench_sender->poll_counter += 1;

	// remember the time!
    bench_sender->last_tx = time;
}

void
log_bench_sender(struct bench_sender_t *bs) {
	RTE_LOG(INFO, BENCH_SENDER, "------------- Bench Sender -------------\n");
//	RTE_LOG(INFO, BENCH_SENDER, "| Core ID:             %"PRIu16"\n", bs->core_id);
//	RTE_LOG(INFO, BENCH_SENDER, "| Out port:            %"PRIu16"\n", bs->output_port);
	RTE_LOG(INFO, BENCH_SENDER, "| Source MAC:          "FORMAT_MAC"\n", ARG_V_MAC(bs->src_mac));
	RTE_LOG(INFO, BENCH_SENDER, "| Destination MAC:     "FORMAT_MAC"\n", ARG_V_MAC(bs->dst_mac));
	RTE_LOG(INFO, BENCH_SENDER, "| Source IP:           "FORMAT_IP"\n", ARG_V_IP(bs->src_ip));
	RTE_LOG(INFO, BENCH_SENDER, "| Destination IP:      "FORMAT_IP"\n", ARG_V_IP(bs->dst_ip));
	RTE_LOG(INFO, BENCH_SENDER, "| UDP estination port: %"PRIu16"\n", bs->dst_udp_port);
	// RTE_LOG(INFO, BENCH_SENDER, "| Packet interval:     %"PRIu64"us\n", bs->packet_interval);
	RTE_LOG(INFO, BENCH_SENDER, "| Packet send:         %"PRIu64"\n", bs->pkts_send);
	if (bs->poll_counter != 0)
		RTE_LOG(INFO, BENCH_SENDER, "| send per poll:       %"PRIu64"\n", bs->pkts_counter / bs->poll_counter);
	RTE_LOG(INFO, BENCH_SENDER, "| Sequence:            %"PRIu64"\n", bs->cur_sequence);
	RTE_LOG(INFO, BENCH_SENDER, "----------------------------------------\n");
	bs->pkts_counter = 0;
	bs->poll_counter = 0;
}

static int
read_mac(config_setting_t *bs_conf, const char *name, struct ether_addr *mac) {
	const char *omac;
	if (config_setting_lookup_string(bs_conf, name, &omac) == CONFIG_TRUE) {
		if (parse_mac(omac, mac) != 0) {
			RTE_LOG(ERR, BENCH_SENDER, "Source MAC has wrong format.\n");
			return 1;
		}
	} else {
		RTE_LOG(ERR, BENCH_SENDER, "Could not read mac.\n");
		return 1;
	}
	return 0;
}

static int
read_ip(config_setting_t *bs_conf, const char *name, uint32_t *ip) {
	const char *ip_str;
	// get IP out of config file
	if (config_setting_lookup_string(bs_conf, name, &ip_str) == CONFIG_TRUE) {
		// parse IP (string to int)
		if (parse_ip(ip_str, ip) != 0) {
			RTE_LOG(ERR, BENCH_SENDER, "Source IP has wrong format.\n");
			return 1;
		}
	} else {
		RTE_LOG(ERR, BENCH_SENDER, "Could not read ip.\n");
		return 1;
	}
	return 0;
}

static int
get_sequence(config_setting_t *s_conf, struct bench_sequence_t *sequence) {

	// INTERVAL
	if (config_setting_lookup_int64(s_conf, CN_PKT_PER_SEC, (long long int *) &sequence->pkt_per_sec) != CONFIG_TRUE) {
		RTE_LOG(ERR, BENCH_SENDER, "Could not read %s.\n", CN_PKT_PER_SEC);
		return 1;
	}

	// PACKET NUMBER
	if (config_setting_lookup_int64(s_conf, CN_PACKET_NB, (long long int *) &sequence->nb_packets) != CONFIG_TRUE) {
		RTE_LOG(ERR, BENCH_SENDER, "Could not read %s.\n", CN_PACKET_NB);
		return 1;
	}

	// PACKET SIZE
	if (config_setting_lookup_int64(s_conf, CN_PACKET_SIZE, (long long int *) &sequence->packet_size) != CONFIG_TRUE) {
		RTE_LOG(ERR, BENCH_SENDER, "Could not read %s.\n", CN_PACKET_SIZE);
		return 1;
	}

	sequence->nb_packets_send = 0;

	return 0;
}

int
get_bench_sender(config_setting_t *bs_conf, 
				struct app_config *appconfig, 
				struct bench_sender_t *bench_sender) {

	// CORE ID
	if (config_setting_lookup_int(bs_conf, CN_CORE_ID, &bench_sender->core_id) != CONFIG_TRUE) {
		RTE_LOG(ERR, BENCH_SENDER, "Could not read %s.\n", CN_CORE_ID);
		return 1;
	}

	// OUT PORT
	if (config_setting_lookup_int(bs_conf, CN_OUT_PORT, &bench_sender->output_port) != CONFIG_TRUE) {
		RTE_LOG(ERR, BENCH_SENDER, "Could not read %s.\n", CN_OUT_PORT);
		return 1;
	}

	// SOURCE MAC
	rte_eth_macaddr_get(bench_sender->output_port, &bench_sender->src_mac);

	//DESTINATION MAC
	if (read_mac(bs_conf, CN_DST_MAC, &bench_sender->dst_mac) != 0) {
		RTE_LOG(ERR, BENCH_SENDER, "Could not read %s.\n", CN_DST_MAC);
		return 1;
	}

	// SOURCE IP
	if (read_ip(bs_conf, CN_SRC_IP, &bench_sender->src_ip) != 0) {
		RTE_LOG(ERR, BENCH_SENDER, "Could not read %s.\n", CN_SRC_IP);
		return 1;
	}

	//DESTINATION IP
	if (read_ip(bs_conf, CN_DST_IP, &bench_sender->dst_ip) != 0) {
		RTE_LOG(ERR, BENCH_SENDER, "Could not read %s.\n", CN_DST_IP);
		return 1;
	}

	{
		// UDP OUT PORT
		int read;
		if (config_setting_lookup_int(bs_conf, CN_DST_UPD_PORT, &read) != CONFIG_TRUE) {
			RTE_LOG(ERR, BENCH_SENDER, "Could not read outgiong UDP port number.\n");
			return 1;
		}
		bench_sender->dst_udp_port = read;
	}

	// bench sequences
	{
		config_setting_t *sequences_conf = config_setting_lookup(bs_conf, CN_SEQUENCE);
		if (sequences_conf == NULL) {
			RTE_LOG(INFO, BENCH_SENDER, "No sequence.");
			return 0;
		}
		bench_sender->nb_sequences = config_setting_length(sequences_conf);
		bench_sender->cur_sequence = 0;
		RTE_LOG(INFO, BENCH_SENDER, "Allocate memory for %"PRIu64" sequences.\n", bench_sender->nb_sequences);
	
		// memory for array of forwarder pointer
		bench_sender->sequences = rte_malloc(NULL, sizeof(struct bench_sequence_t*)
										 * bench_sender->nb_sequences, 64);
	
		// init forwarder and add it to the forwarder array in app_config
		for (size_t i = 0; i < bench_sender->nb_sequences; ++i) {
			RTE_LOG(INFO, BENCH_SENDER, "New sequence!\n");
			config_setting_t *s_conf = config_setting_get_elem(sequences_conf, i);
			struct bench_sequence_t *sequence = rte_malloc(NULL, sizeof(struct bench_sequence_t), 64);

			if (get_sequence(s_conf, sequence) != 0) {
				RTE_LOG(ERR, BENCH_SENDER, "Could not set up sequence.\n");
				rte_free(sequence);
				rte_free(bench_sender->sequences);
				return 1;
			}
			bench_sender->sequences[i] = sequence;
		}
	}
	clock_t c_time = clock();
	bench_sender->last_tx = ms_to_us(s_to_ms(c_time / CLOCKS_PER_SEC));

	bench_sender->pkt_pool = appconfig->pkt_pool;
	bench_sender->clone_pool = appconfig->clone_pool;
	bench_sender->pkts_send = 0;
	bench_sender->pkts_counter = 0;
	bench_sender->poll_counter = 0;
	bench_sender->send_buf = rte_malloc(NULL, sizeof(void*) * BURST_SIZE, 64);

	uint64_t msg[2];
	bench_sender->prototype = gen_packet(bench_sender, NULL, 2);

	log_bench_sender(bench_sender);
	return 0;
}