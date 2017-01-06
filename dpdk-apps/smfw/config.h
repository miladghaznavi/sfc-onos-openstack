#ifndef CONFIG_H_
#define CONFIG_H_

#define CN_LOG_POOL_SIZE            "log_mempool_size"
#define CN_CORES                    "cores"
#define CN_PORTMASK                 "port_mask"
#define CN_RECEIVE_ON_CORES         "receive_on_cores"
        
#define CN_CORE_ID                  "core_id"
        
#define CN_OUT_PORT                 "out_port"
#define CN_IN_PORT                  "in_port"
        
#define CN_SRC_MAC                  "src_mac"
#define CN_DST_MAC                  "dst_mac"
#define CN_MAC                      "mac"
#define CN_DST                      "dst"
        
#define CN_SRC_IP                   "src_ip"
#define CN_DST_IP                   "dst_ip"
        
#define CN_SRC_UPD_PORT             "src_udp_port"
#define CN_DST_UPD_PORT             "dst_udp_port"
        
#define CN_PKT_PER_SEC              "packet_per_sec"
        
        
#define CN_TX_ID                    "sender_id"
#define CN_RX_ID                    "receiver_id"
        
/*      
 * Component identifier:        
 */     
#define CN_SENDER                   "sender"
#define CN_FORWARDERS               "forwarder"
#define CN_COUNTER                  "counter"
#define CN_BENCH_SENDERS            "bench_senders"
#define CN_BENCH_RECEIVERS          "bench_receivers"
#define CN_BENCH_FORWARDERS         "bench_forwarders"
#define CN_ARP_SENDERS              "arp_senders"
#define CN_MIRROWS                  "mirrow"

/*
 * Counter configurable fields
 */
#define CN_RX_REGISTER_ID           "register_rx_id"
#define CN_RX_FIREWALL_ID           "firewall_rx_id"

#define CN_NEXT_VNF_MAC             "next_vnf_mac"
#define CN_FW_MAC                   "fw_mac"
        
#define CN_ENCAP_ON_REGISTER        "encap_on_register"
#define CN_DECAP_ON_SEND            "decap_on_send"

#define CN_DROP_AT                  "drop_if_less_than"
#define CN_RING_SIZE_LOG            "ring_size_log"
#define CN_TABLE_SIZE               "table_size"
#define CN_BUCKET_PER_ENTRY         "buckets_per_entry"

#define CN_TIMEOUT                  "timeout"

#define CN_CHAIN_INDEX              "chain_index"

/*
 * Bench configurable fields
 */

#define CN_SEQUENCE                 "sequence"
#define CN_PACKET_NB                "packet_nb"
#define CN_PACKET_SIZE              "packet_size"

#define CN_LOG_NAMES                "sequence_log_name"
#define CN_LOG_FILE                 "log_file"

#define CN_LOG_PACKETS              "log_packets"

#define CN_PCKT_DELAY               "delay"
#define CN_COMPRESS                 "compress"

#endif /* CONFIG_H_ */
