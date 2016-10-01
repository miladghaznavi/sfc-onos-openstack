#ifndef PARSE_H_
#define PARSE_H_

#include <inttypes.h>

#include <rte_ether.h>
#include <rte_byteorder.h>

#define FORMAT_MAC "%02X:%02X:%02X:%02X:%02X:%02X"
#define ARG_V_MAC(X) X.addr_bytes[0], X.addr_bytes[1], X.addr_bytes[2], X.addr_bytes[3], X.addr_bytes[4], X.addr_bytes[5]

#define FORMAT_IP "%d.%d.%d.%d"
#define ARG_V_IP(X) rte_be_to_cpu_32(X) & 0xFF, (rte_be_to_cpu_32(X) >> 8) & 0xFF, (rte_be_to_cpu_32(X) >> 16) & 0xFF, (rte_be_to_cpu_32(X) >> 24) & 0xFF

int
parse_mac(const char *mac_str, struct ether_addr *mac);

int
parse_ip(const char *ips, uint32_t* ip);

void
print_packet_hex(struct rte_mbuf* m);

void
print_packet(struct rte_mbuf* m, int has_meta);

#endif /* PARSE_H_ */
