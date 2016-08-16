#ifndef PARSE_H_
#define PARSE_H_

#include <inttypes.h>

#include <rte_ether.h>

#define FORMAT_MAC "%02X:%02X:%02X:%02X:%02X:%02X"
#define ARG_V_MAC(X) X.addr_bytes[0], X.addr_bytes[1], X.addr_bytes[2], X.addr_bytes[3], X.addr_bytes[4], X.addr_bytes[5]

#define FORMAT_IP "%d.%d.%d.%d"
#define ARG_V_IP(X) (X >> 24) & 0xFF, (X >> 16) & 0xFF, (X >> 8) & 0xFF, X & 0xFF

int
parse_mac(const char *mac_str, struct ether_addr *mac);

int
parse_ip(const char *ips, uint32_t* ip);

#endif /* PARSE_H_ */
