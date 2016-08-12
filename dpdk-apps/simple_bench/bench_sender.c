/* 
 * 
 * 
 * 
 * 
 * 
 * 
 */

#include "bench_sender.h"

#include "parse.h"
#include "config.h"

#include <stdlib.h>
#include <inttypes.h>
#include <time.h>
#include <libconfig.h>

#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_udp.h>
#include <rte_ethdev.h>
#include <rte_cycles.h>

#define RTE_LOGTYPE_BENCH_SENDER RTE_LOGTYPE_USER3

#define SOURCE_UDP_PORT 0
#define CLOCKS_PER_MS CLOCKS_PER_SEC / 100
#define BENCH_INTERVAL 50


static void
send_packet(struct bench_sender_t *bench_sender, char* msg, uint32_t msg_size) {
    uint32_t pkt_size;
    struct ether_hdr *eth_hdr;
    struct ipv4_hdr *ip_hdr;
    struct udp_hdr *udp_hdr;
    char* msg_start;
    struct rte_mbuf* m_array[1];

    pkt_size = sizeof(struct ether_hdr) + sizeof(struct ipv4_hdr) 
                + sizeof(struct udp_hdr) + msg_size * sizeof(char);
    
    m_array[0] = rte_pktmbuf_alloc(bench_sender->cloned_pool);
    struct rte_mbuf *m = m_array[0];

    m->data_len = pkt_size;
    m->pkt_len = pkt_size;

    eth_hdr = rte_pktmbuf_mtod(m, struct ether_hdr *);
    ether_addr_copy(&eth_hdr->s_addr, &bench_sender->src_mac);
    ether_addr_copy(&eth_hdr->d_addr, &bench_sender->dst_mac);
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

    int send = rte_eth_tx_burst(bench_sender->output_port, 0, m_array, 1);
    if (send > 0) {
        bench_sender->pkts_send++;
    }
}

/*
 * This lcore sends udp packets containing a timestamp.
 */
void
send_bench_packet(struct bench_sender_t *bench_sender) {

    bench_sender->tm_last_pkt_send = clock();
    send_packet(bench_sender, (char*) &bench_sender->tm_last_pkt_send, sizeof(bench_sender->tm_last_pkt_send));
}

void
bench_send_poll(struct bench_sender_t* bench_sender) {
    uint64_t tm = clock();

    if (tm - bench_sender->tm_last_pkt_send > CLOCKS_PER_MS) {
        send_bench_packet(bench_sender);
    }
}

void
log_bench_sender(struct bench_sender_t *bs) {
    RTE_LOG(INFO, BENCH_SENDER, "------------- Bench Sender -------------\n");
    RTE_LOG(INFO, BENCH_SENDER, "| Core ID:             %"PRIu16"\n", bs->core_id);
    RTE_LOG(INFO, BENCH_SENDER, "| Out port:            %"PRIu16"\n", bs->output_port);
    RTE_LOG(INFO, BENCH_SENDER, "| Source MAC:          "FORMAT_MAC"\n", ARG_V_MAC(bs->src_mac));
    RTE_LOG(INFO, BENCH_SENDER, "| Destination MAC:     "FORMAT_MAC"\n", ARG_V_MAC(bs->dst_mac));
    RTE_LOG(INFO, BENCH_SENDER, "| Source IP:           "FORMAT_IP"\n", ARG_V_IP(bs->src_ip));
    RTE_LOG(INFO, BENCH_SENDER, "| Destination IP:      "FORMAT_IP"\n", ARG_V_IP(bs->dst_ip));
    RTE_LOG(INFO, BENCH_SENDER, "| UDP estination port: %"PRIu16"\n", bs->dst_udp_port);
    RTE_LOG(INFO, BENCH_SENDER, "| Packet interval:     %"PRIu64"ms\n", bs->packet_interval);
    RTE_LOG(INFO, BENCH_SENDER, "| Packet send:         %"PRIu64"\n", bs->pkts_send);
    RTE_LOG(INFO, BENCH_SENDER, "----------------------------------------\n\n");
}

static int
read_mac(config_setting_t *bs_conf, const char *name, struct ether_addr *mac) {
    const char * omac;
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
read_ip(config_setting_t *bs_conf, const char *name, uint32_t* ip) {
    const char * ip_str;
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

int
read_send_bench(config_setting_t *bs_conf, 
                struct rte_mempool *cloned_pool, 
                struct bench_sender_t * bench_sender) {


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

    // Time between packets
    {
        int read;
        if (config_setting_lookup_int(bs_conf, CN_PKT_INTERVAL, &read) != CONFIG_TRUE) {
            RTE_LOG(ERR, BENCH_SENDER, "Could not read packet interval.\n");
            return 1;
        }
        bench_sender->packet_interval = read;
    }

    bench_sender->tm_last_pkt_send = 0;
    bench_sender->pkts_send = 0;

    log_bench_sender(bench_sender);
    return 0;
}