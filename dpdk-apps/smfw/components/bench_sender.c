/*
 *
 */

#include "bench_sender.h"

#include "../parse.h"
#include "../rxtx.h"
#include "../config.h"
#include "../init.h"
#include "receiver.h"
#include "wrapping.h"

#include <stdlib.h>
#include <inttypes.h>
#include <time.h>
#include <sys/time.h>
#include <libconfig.h>
#include <math.h>

#include <rte_malloc.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_udp.h>
#include <rte_ethdev.h>
#include <rte_cycles.h>

#define RTE_LOGTYPE_BENCH_SENDER RTE_LOGTYPE_USER3

#define SOURCE_UDP_PORT 0
#define BUFF_TIME_B4_SWITCH 2000 //ms
#define BUFF_TIME_AFTR_SWITCH 2000 //ms

struct rte_mbuf *
gen_prototype(struct bench_sender_t *bench_sender, uint32_t msg_size, uint32_t ip_size, size_t i_mac) {
	struct ether_hdr *eth_hdr;
	struct ipv4_hdr *ip_hdr;
	struct udp_hdr *udp_hdr;

	// generate prototype packet:
	uint32_t hdr_size = sizeof(struct ether_hdr) + sizeof(struct ipv4_hdr) + sizeof(struct udp_hdr);

	struct rte_mbuf *m = rte_pktmbuf_alloc(bench_sender->pkt_pool);
	if (m == NULL || m->buf_len <= hdr_size) {
		RTE_LOG(ERR, BENCH_SENDER, "mbuf alloc failed!\n");
		die();
	}
	RTE_LOG(INFO, BENCH_SENDER, "alloc mbuf for prototype\n");
	m->data_len = hdr_size;
	m->pkt_len = m->data_len;
	eth_hdr = rte_pktmbuf_mtod(m, struct ether_hdr *);

	ether_addr_copy(&bench_sender->tx->send_port_mac, &eth_hdr->s_addr);
	ether_addr_copy(&bench_sender->dst_macs[i_mac], &eth_hdr->d_addr);
	eth_hdr->ether_type = rte_cpu_to_be_16(ETHER_TYPE);
	
	ip_hdr = rte_pktmbuf_mtod_offset(m, struct ipv4_hdr *, sizeof(struct ether_hdr));

	ip_hdr->version_ihl = 0x45;
	ip_hdr->time_to_live = 0xF;
	ip_hdr->src_addr = rte_cpu_to_be_32(bench_sender->src_ip);
	ip_hdr->dst_addr = rte_cpu_to_be_32(bench_sender->dst_ip);
	ip_hdr->next_proto_id = IPPROTO_UDP;

	ip_hdr->total_length = rte_cpu_to_be_16(ip_size);
	
	ip_hdr->hdr_checksum = 0;
	ip_hdr->hdr_checksum  = rte_ipv4_cksum(ip_hdr);
	
	udp_hdr = rte_pktmbuf_mtod_offset(m, struct udp_hdr *, 
		sizeof(struct ether_hdr) + sizeof(struct ipv4_hdr));

	udp_hdr->src_port = SOURCE_UDP_PORT;
	udp_hdr->dst_port = rte_cpu_to_be_16(bench_sender->dst_udp_port);
	udp_hdr->dgram_len = rte_cpu_to_be_16(msg_size + sizeof(struct udp_hdr));

	return m;
}

/*
 * Generates a packet which is a clone of a prototype.
 * msg_size -> size of upd payload
 * ip_size -> size of ip payload
 */
static struct rte_mbuf *
gen_packet(struct bench_sender_t *bench_sender, char *msg, size_t msg_size, uint32_t ip_size, size_t i_mac) {
	
	if (bench_sender->prototype_ip_size != ip_size) 
	for (int i = 0; i < bench_sender->nb_dst_macs; i++) {

		struct ether_hdr *eth_hdr = rte_pktmbuf_mtod(bench_sender->prototypes[i], struct ether_hdr *);
		struct ipv4_hdr *ip_hdr = rte_pktmbuf_mtod_offset(bench_sender->prototypes[i], struct ipv4_hdr *, sizeof(struct ether_hdr));
		struct udp_hdr *udp_hdr = rte_pktmbuf_mtod_offset(bench_sender->prototypes[i], struct udp_hdr *, 
			sizeof(struct ether_hdr) + sizeof(struct ipv4_hdr));

		ip_hdr->total_length = rte_cpu_to_be_16(ip_size);
		ip_hdr->hdr_checksum = 0;
		ip_hdr->hdr_checksum  = rte_ipv4_cksum(ip_hdr);
		udp_hdr->dgram_len = rte_cpu_to_be_16(msg_size + sizeof(struct udp_hdr));
		bench_sender->prototype_ip_size = ip_size;
	}
	

	struct rte_mbuf *hdr_mbuf = rte_pktmbuf_clone(bench_sender->prototypes[i_mac], bench_sender->clone_pool);
	struct rte_mbuf *msg_mbuf = rte_pktmbuf_alloc(bench_sender->pkt_pool);
	
	if (msg_mbuf == NULL) {
		RTE_LOG(ERR, BENCH_SENDER, "Could not alloc mBUF.\n");
	} else if (hdr_mbuf == NULL) {
		RTE_LOG(ERR, BENCH_SENDER, "Could not clone mBUF.\n");
	}
	msg_mbuf->data_len = ip_size - sizeof(struct udp_hdr) - sizeof(struct ipv4_hdr);
	msg_mbuf->pkt_len = msg_mbuf->data_len;

	uint64_t*msg_start = rte_pktmbuf_mtod(msg_mbuf, uint64_t*);
	memset(msg_start, 0, sizeof(char)*ip_size - sizeof(struct ipv4_hdr)-sizeof(struct udp_hdr));

	if (msg != NULL) memcpy(msg_start, msg, msg_size);

	rte_pktmbuf_chain(hdr_mbuf, msg_mbuf);

	return hdr_mbuf;
}

bool
should_wait(struct bench_sender_t *bench_sender, uint64_t time) {	
	struct bench_sequence_t *sequence = bench_sender->sequences[bench_sender->cur_sequence];
	uint64_t last_tx_us = bench_sender->last_tx * 1000000 / rte_get_tsc_hz();
	uint64_t time_us = time * 1000000 / rte_get_tsc_hz();

	// check if we have to wait between sequences
	if (likely(sequence->nb_packets_send < sequence->nb_packets)) return false;

	// sequence N -- NOW --- END-SEQ-PCKT ----- sequence N+1 (or end...)
	if (time_us - last_tx_us > ms_to_us(BUFF_TIME_B4_SWITCH) && 
						sequence->nb_packets_send <= sequence->nb_packets) {

		uint64_t msg[2];
		msg[0] = STOP_SEQ;
		msg[1] = time_us;

		struct rte_mbuf *m[bench_sender->nb_dst_macs];
		for (int i = 0; i < bench_sender->nb_dst_macs; i++)
			m[i] = gen_packet(bench_sender, (char *) msg, sizeof(uint64_t) *2, 100, i);
		
		int send = 0;
		while (send < bench_sender->nb_dst_macs) {
			send += tx_put(bench_sender->tx, m + send, bench_sender->nb_dst_macs - send);
		}
		sequence->nb_packets_send++;

	} else if (time_us - last_tx_us > 
		ms_to_us(BUFF_TIME_B4_SWITCH) + ms_to_us(BUFF_TIME_AFTR_SWITCH)) {
	// sequence N ----- (END-SEQ-PCKT) ------ NOW ----- sequence N+1 (or end...)
		bench_sender->cur_sequence++;
		bench_sender->last_tx = time;
	}
	return true;
}

void
poll_bench_sender(struct bench_sender_t *bench_sender) {

	if (unlikely(bench_sender->cur_sequence >= bench_sender->nb_sequences)) return;
	if (unlikely(bench_sender->last_tx == 0)) 
		bench_sender->last_tx = rte_get_tsc_cycles();

	// get time and current sequence config
	uint64_t time = rte_get_tsc_cycles();
	uint64_t last_tx_us = bench_sender->last_tx * 1000000 / (double) rte_get_tsc_hz();
	struct bench_sequence_t *sequence = bench_sender->sequences[bench_sender->cur_sequence];

	// check if we should wait and send nothing
	if (should_wait(bench_sender, time)) return;

	// determine the number of packets to send
	double elapsed_time = time - bench_sender->last_tx;
	uint64_t send_count = elapsed_time * sequence->pkt_per_sec / (double) rte_get_tsc_hz();

	// check that packet count is valid
	if (send_count == 0) return;
	else if (send_count > BURST_SIZE) send_count = BURST_SIZE;
	bench_sender->should_pkts_counter += send_count;

	// generate the packets
	uint64_t nb_packets_send = sequence->nb_packets_send;
	for (size_t i = 0; i < send_count; ++i) {
		if (nb_packets_send >= sequence->nb_packets) {
			send_count = i;
			break;
		}
		uint64_t msg[2];
		msg[0] = nb_packets_send;
		msg[1] = time * 1000000 / (double) rte_get_tsc_hz();

		for (int i_mac = 0; i_mac < bench_sender->nb_dst_macs; i_mac++) {
			struct rte_mbuf *pkt = gen_packet(bench_sender, (char *) msg, 
								sizeof(uint64_t) *2, sequence->ip_size, i_mac);

			if (bench_sender->should_compress[i_mac]) {
				uint64_t start = rte_get_tsc_cycles(), diff;
				wrapper_compress(bench_sender->pkt_pool, pkt);
			    diff = rte_get_tsc_cycles() - start;
			    bench_sender->time += diff;// * 1000.0 / rte_get_tsc_hz();
			    bench_sender->nb_measurements++;
			}

			bench_sender->send_buf[i_mac][i] = pkt;
		}
		nb_packets_send++;
	}

	// send the generated packets
	// int send = tx_put(bench_sender->tx, bench_sender->send_buf, send_count);
	int send;
	for (int i_mac = 0; i_mac < bench_sender->nb_dst_macs; i_mac++) {
		send = 0;
		while (send < send_count) {
			send += tx_put(bench_sender->tx, (bench_sender->send_buf[i_mac] + send), send_count - send);
		}
	}
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
	RTE_LOG(INFO, BENCH_SENDER, "| Source MAC:          "FORMAT_MAC"\n", ARG_V_MAC(bs->tx->send_port_mac));
	for (int i=0; i<bs->nb_dst_macs; i++)
		RTE_LOG(INFO, BENCH_SENDER, "| Destination MAC:     "FORMAT_MAC"\n", ARG_V_MAC(bs->dst_macs[i]));
	RTE_LOG(INFO, BENCH_SENDER, "| Source IP:           "FORMAT_IP"\n", ARG_V_IP(bs->src_ip));
	RTE_LOG(INFO, BENCH_SENDER, "| Destination IP:      "FORMAT_IP"\n", ARG_V_IP(bs->dst_ip));
	RTE_LOG(INFO, BENCH_SENDER, "| UDP estination port: %"PRIu16"\n", bs->dst_udp_port);
	RTE_LOG(INFO, BENCH_SENDER, "| Packet send:         %"PRIu64"\n", bs->pkts_send);
	if (bs->poll_counter != 0)
		RTE_LOG(INFO, BENCH_SENDER, "| send per poll:       %.2f/%"PRIu64"\n", 
			bs->pkts_counter / (float)bs->poll_counter, bs->should_pkts_counter / bs->poll_counter);
	RTE_LOG(INFO, BENCH_SENDER, "| Sequence:            %"PRIu64"/%"PRIu64"\n", bs->cur_sequence, bs->nb_sequences);
	if (bs->cur_sequence < bs->nb_sequences)
		RTE_LOG(INFO, BENCH_SENDER, "| - progress:      %"PRIu64"/%"PRIu64"\n", 
			bs->sequences[bs->cur_sequence]->nb_packets_send, 
			bs->sequences[bs->cur_sequence]->nb_packets);
	if (bs->nb_measurements != 0)
		RTE_LOG(INFO, BENCH_SENDER, "| wrapping CPU cycle:%.2f\n", 
			bs->time / bs->nb_measurements);
	RTE_LOG(INFO, BENCH_SENDER, "----------------------------------------\n");
	bs->pkts_counter = 0;
	bs->should_pkts_counter = 0;
	bs->poll_counter = 0;
}

static int
read_mac(const char *mac_str, struct ether_addr *mac) {
	if (parse_mac(mac_str, mac) != 0) {
		RTE_LOG(ERR, BENCH_SENDER, "Source MAC has wrong format.\n");
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
	if (config_setting_lookup_int64(s_conf, CN_PACKET_SIZE, (long long int *) &sequence->ip_size) != CONFIG_TRUE) {
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
	
	RTE_LOG(INFO, BENCH_SENDER, "INIT Bench sender:\n");
	// CORE ID
	if (config_setting_lookup_int(bs_conf, CN_CORE_ID, &bench_sender->core_id) != CONFIG_TRUE) {
		RTE_LOG(ERR, BENCH_SENDER, "Could not read %s.\n", CN_CORE_ID);
		return 1;
	}

	// sender
	unsigned sender_i;
	if (config_setting_lookup_int(bs_conf, CN_TX_ID, &sender_i) != CONFIG_TRUE) {
		RTE_LOG(ERR, BENCH_SENDER, "Could not read sender index.\n");
		return 1;
	}

	if (sender_i > appconfig->nb_sender) {
		RTE_LOG(ERR, BENCH_SENDER, "Sender index out of bounds. (%"PRIu32" of %"PRIu32" )\n", sender_i, appconfig->nb_sender);
		return 1;
	}
	bench_sender->tx = appconfig->sender[sender_i];

	//DESTINATION MAC
	config_setting_t *dst_mac_conf = config_setting_get_member(bs_conf, CN_DST);
	if (dst_mac_conf == NULL) {
		RTE_LOG(INFO, BENCH_SENDER, "No dst macs found.\n");
		return 1;
	}
	bench_sender->nb_dst_macs = config_setting_length(dst_mac_conf);
	RTE_LOG(INFO, BENCH_SENDER, "Got %ld dst MACs\n", bench_sender->nb_dst_macs);
	bench_sender->dst_macs = rte_malloc(NULL, sizeof(struct ether_addr)
										 * bench_sender->nb_dst_macs, 64);
	bench_sender->should_compress = rte_malloc(NULL, sizeof(bool)
										 * bench_sender->nb_dst_macs, 64);

	for (size_t i = 0; i < bench_sender->nb_dst_macs; ++i) {
		config_setting_t *d_cfg = config_setting_get_elem(dst_mac_conf, i);

		const char *mac_str;
		if (config_setting_lookup_string(d_cfg, CN_MAC, &mac_str) != CONFIG_TRUE) {
			RTE_LOG(ERR, BENCH_SENDER, "error in bench sender config.\n");
			return 1; 
		}
		if (read_mac(mac_str, bench_sender->dst_macs + i) != 0) {
			RTE_LOG(ERR, BENCH_SENDER, "error in bench sender config.\n");
			return 1;
		}
		
		int should_compress;
		if (config_setting_lookup_bool(d_cfg, CN_COMPRESS, &should_compress) != CONFIG_TRUE) {
			RTE_LOG(ERR, BENCH_SENDER, "Could not read %s.\n", CN_COMPRESS);
			return 1;
		}
		bench_sender->should_compress[i] = (bool) should_compress;
		RTE_LOG(INFO, BENCH_SENDER, "Mac: "FORMAT_MAC" Compress: %d\n", 
			ARG_V_MAC(bench_sender->dst_macs[i]), should_compress);
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
		config_setting_t *sequences_conf = config_setting_get_member(bs_conf, CN_SEQUENCE);
		if (sequences_conf == NULL) {
			RTE_LOG(INFO, BENCH_SENDER, "No sequence.\n");
			return 1;
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

	bench_sender->pkt_pool = appconfig->pkt_pool;
	bench_sender->clone_pool = appconfig->clone_pool;
	bench_sender->pkts_send = 0;
	bench_sender->pkts_counter = 0;
	bench_sender->poll_counter = 0;
	bench_sender->last_tx = 0;
	bench_sender->nb_prototypes = bench_sender->nb_dst_macs;
	bench_sender->prototypes = rte_malloc(NULL, sizeof(void*) * bench_sender->nb_prototypes, 64);
	bench_sender->send_buf = rte_malloc(NULL, sizeof(void*) * bench_sender->nb_dst_macs, 64);

	for (int i = 0; i < bench_sender->nb_dst_macs; i++) {
		bench_sender->prototypes[i] = gen_prototype(bench_sender, 100, 150, i);
		bench_sender->send_buf[i] = rte_malloc(NULL, sizeof(void*) * BURST_SIZE, 64);
	}

	bench_sender->prototype_ip_size = 150;

	log_bench_sender(bench_sender);
	return 0;
}
