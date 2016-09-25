/*
 *
 */

#include "bench_sender.h"

#include "parse.h"
#include "config.h"

#include <stdlib.h>
#include <inttypes.h>
#include <time.h>
#include <sys/time.h>
#include <libconfig.h>

#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_udp.h>
#include <rte_ethdev.h>
#include <rte_cycles.h>

#define RTE_LOGTYPE_BENCH_SENDER RTE_LOGTYPE_USER3

#define SOURCE_UDP_PORT 0

static int
send_packet(struct bench_sender_t *bench_sender, char *msg, uint32_t msg_size) {
	uint32_t pkt_size;
	struct ether_hdr *eth_hdr;
	struct ipv4_hdr *ip_hdr;
	struct udp_hdr *udp_hdr;
	char*msg_start;
	struct bench_sequence_t *sequence;

	sequence = bench_sender->sequences[bench_sender->cur_sequence];

	pkt_size = sizeof(struct ether_hdr) + sequence->packet_size;
	
	struct rte_mbuf *m = rte_pktmbuf_alloc(bench_sender->cloned_pool);
	if (m == NULL || m->buf_len <= pkt_size) {
		RTE_LOG(ERR, BENCH_SENDER, "mbuf alloc failed!\n");
		return 0;
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
	memcpy(msg_start, msg, msg_size);

	udp_hdr->dgram_cksum = rte_cpu_to_be_16(rte_ipv4_udptcp_cksum(ip_hdr, (const void *) udp_hdr));

	int send = rte_eth_tx_burst(bench_sender->output_port, 0, &m, 1);

	if (send > 0) {
		bench_sender->pkts_send++;
		sequence->nb_packets_send++;
	} else {
		rte_pktmbuf_free(m);
	}
	return send;
}

void
poll_bench_sender(struct bench_sender_t *bench_sender) {
	if (bench_sender->cur_sequence >= bench_sender->nb_sequences) return;

	struct bench_sequence_t *sequence;
	struct timeval time_val;
	gettimeofday(&time_val, NULL);


	u_second_t time = ms_to_us(s_to_ms(time_val.tv_sec)) + time_val.tv_usec;

	if (bench_sender->wait < time - bench_sender->last_poll) {
		uint64_t send_vals[2];
		sequence = bench_sender->sequences[bench_sender->cur_sequence];

		send_vals[0] = sequence->nb_packets_send;
		send_vals[1] = time;

		// if last packet, wait, send end sequence code, wait
		if (sequence->nb_packets_send+1 == sequence->nb_packets) {
			bench_sender->wait = ms_to_us(s_to_ms(2));
        	bench_sender->last_poll = time;
        	sequence->nb_packets_send++;
        	return;
        } else if (sequence->nb_packets_send+1 >= sequence->nb_packets) {
			send_vals[0] = STOP_SEQ;
        }

		int send = send_packet(bench_sender, (char*) &send_vals, sizeof(time) *2);

		// if packet was send
		if (send_vals[0] == STOP_SEQ && send > 0) {
			bench_sender->cur_sequence++;
			bench_sender->wait = ms_to_us(s_to_ms(2));
		}
        bench_sender->wait = sequence->packet_interval;
        bench_sender->last_poll = time;
	}
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
	RTE_LOG(INFO, BENCH_SENDER, "| Sequence:            %"PRIu64"\n", bs->cur_sequence);
	RTE_LOG(INFO, BENCH_SENDER, "----------------------------------------\n");
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
	if (config_setting_lookup_int64(s_conf, CN_PKT_INTERVAL, (long long int *) &sequence->packet_interval) != CONFIG_TRUE) {
		RTE_LOG(ERR, BENCH_SENDER, "Could not read %s.\n", CN_PKT_INTERVAL);
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
				struct rte_mempool *cloned_pool, 
				struct bench_sender_t *bench_sender) {


	bench_sender->cloned_pool = cloned_pool;

	// CORE ID
	if (config_setting_lookup_int(bs_conf, CN_CORE_ID, &bench_sender->core_id) != CONFIG_TRUE) {
		RTE_LOG(ERR, BENCH_SENDER, "Could not read core id.\n");
		return 1;
	}

	// OUT PORT
	if (config_setting_lookup_int(bs_conf, CN_OUT_PORT, &bench_sender->output_port) != CONFIG_TRUE) {
		RTE_LOG(ERR, BENCH_SENDER, "Could not read outgiong port number.\n");
		return 1;
	}

	// SOURCE MAC
	rte_eth_macaddr_get(bench_sender->output_port, &bench_sender->src_mac);

	//DESTINATION MAC
	if (read_mac(bs_conf, CN_DST_MAC, &bench_sender->dst_mac) != 0) {
		RTE_LOG(ERR, BENCH_SENDER, "Could not read dastination MAC.\n");
		return 1;
	}

	// SOURCE IP
	if (read_ip(bs_conf, CN_SRC_IP, &bench_sender->src_ip) != 0) {
		RTE_LOG(ERR, BENCH_SENDER, "Could not read source IP.\n");
		return 1;
	}

	//DESTINATION IP
	if (read_ip(bs_conf, CN_DST_IP, &bench_sender->dst_ip) != 0) {
		RTE_LOG(ERR, BENCH_SENDER, "Could not read dastination IP.\n");
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
		bench_sender->sequences = malloc(sizeof(struct bench_sequence_t*)
										 * bench_sender->nb_sequences);
	
		// init forwarder and add it to the forwarder array in app_config
		for (size_t i = 0; i < bench_sender->nb_sequences; ++i) {
			RTE_LOG(INFO, BENCH_SENDER, "New sequence!\n");
			config_setting_t *s_conf = config_setting_get_elem(sequences_conf, i);
			struct bench_sequence_t *sequence = malloc(sizeof(struct bench_sequence_t));

			if (get_sequence(s_conf, sequence) != 0) {
				RTE_LOG(ERR, BENCH_SENDER, "Could not set up sequence.\n");
				free(sequence);
				free(bench_sender->sequences);
				return 1;
			}
			bench_sender->sequences[i] = sequence;
		}
	}

	bench_sender->wait = 0;
	bench_sender->last_poll = 0;
	bench_sender->pkts_send = 0;

	log_bench_sender(bench_sender);
	return 0;
}