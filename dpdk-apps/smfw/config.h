#ifndef CONFIG_H_
#define CONFIG_H_

#define CN_CORES              "cores"
#define CN_PORTMASK           "port_mask"
#define CN_RECEIVE_ON_CORES   "receive_on_cores"
  
#define CN_CORE_ID            "core_id"
  
#define CN_OUT_PORT           "out_port"
#define CN_IN_PORT            "in_port"
  
#define CN_SRC_MAC            "src_mac"
#define CN_DST_MAC            "dst_mac"
  
#define CN_SRC_IP             "src_ip"
#define CN_DST_IP             "dst_ip"
  
#define CN_SRC_UPD_PORT       "src_udp_port"
#define CN_DST_UPD_PORT       "dst_udp_port"
  
#define CN_PKT_INTERVAL       "packet_interval"
  
#define CN_LOG_FILE           "log_file"
  
  
#define CN_TX_ID              "sender_id"
#define CN_RX_ID              "receiver_id"
  
/*
 * Component identifier:
 */
#define CN_SENDER             "sender"
#define CN_FORWARDERS         "forwarder"
#define CN_COUNTER            "counter"

/*
 * Counter configurable fields
 */
#define CN_RX_REGISTER_ID     "register_rx_id"
#define CN_RX_FIREWALL_ID     "firewall_rx_id"

#define CN_ENCAP_ON_REGISTER  "encap_on_register"
#define CN_DROP_AT            "drop_if_less_than"
#define CN_RING_SIZE_LOG      "ring_size_log"

#endif /* CONFIG_H_ */
