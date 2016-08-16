#include "counter.h"

#include "../config.h"
#include "../rxtx.h"
#include "../parse.h"
#include "../init.h"

#include <stdlib.h>

#include <rte_ether.h>
#include <rte_log.h>
#include <rte_ring.h>
#include <rte_errno.h>

#define RTE_LOGTYPE_COUNTER RTE_LOGTYPE_USER1

void
counter_register_pkt(void *arg, struct rte_mbuf *m) {

}

void
counter_firewall_pkt(void *arg, struct rte_mbuf *m) {

}

void
log_counter(struct counter_t *counter) {


}

void
poll_counter(struct counter_t *counter) {


}

static int
read_mac(config_setting_t *f_conf, const char *name, struct ether_addr *mac) {
	const char * omac;
	if (config_setting_lookup_string(f_conf, name, &omac) == CONFIG_TRUE) {
		if (parse_mac(omac, mac) != 0) {
			RTE_LOG(ERR, COUNTER, "MAC has wrong format.\n");
			return 1;
		}
	} else {
		RTE_LOG(ERR, COUNTER, "Could not read mac.\n");
		return 1;
	}
	return 0;
}

int
init_counter(config_setting_t *c_conf,
			struct app_config *appconfig, 
			struct counter_t *counter) {

	// sender
	unsigned sender_i;
	if (config_setting_lookup_int(c_conf, CN_TX_ID, &sender_i) != CONFIG_TRUE) {
		RTE_LOG(ERR, COUNTER, "Could not read sender index.\n");
		return 1;
	}

	if (sender_i > appconfig->nb_sender) {
		RTE_LOG(ERR, COUNTER, "Sender index out of bounds. (%"PRIu32" of %"PRIu32" )\n", sender_i, appconfig->nb_sender);
	   return 1;
	}
	counter->tx = appconfig->sender[sender_i];

	// register receive
	{
		unsigned receiver_i;
		if (config_setting_lookup_int(c_conf, CN_RX_REGISTER_ID, &receiver_i) != CONFIG_TRUE) {
			RTE_LOG(ERR, COUNTER, "Could not read receiver index.\n");
			return 1;
		}
	
		if (receiver_i > appconfig->nb_receiver) {
			RTE_LOG(ERR, COUNTER, "Receiver index out of bounds. (%"PRIu32" of %"PRIu32" )\n", receiver_i, appconfig->nb_receiver);
			return 1;
		}
		counter->rx_register = appconfig->receiver[receiver_i];
	}

	// firewall receiver
	{
		unsigned receiver_i;
		if (config_setting_lookup_int(c_conf, CN_RX_FIREWALL_ID, &receiver_i) != CONFIG_TRUE) {
			RTE_LOG(ERR, COUNTER, "Could not read receiver index.\n");
			return 1;
		}
	
		if (receiver_i > appconfig->nb_receiver) {
			RTE_LOG(ERR, COUNTER, "Receiver index out of bounds. (%"PRIu32" of %"PRIu32" )\n", receiver_i, appconfig->nb_receiver);
			return 1;
		}
		counter->rx_firewall = appconfig->receiver[receiver_i];
	}

	// SOURCE MAC
	rte_eth_macaddr_get(counter->tx->port, &counter->send_src_mac);

	//DESTINATION MAC
	if (read_mac(c_conf, CN_DST_MAC, &counter->dst_mac) != 0) {
		RTE_LOG(ERR, COUNTER, "Could not read destination MAC.\n");
		return 1;
	}

	// DROP PACKET AT X VOTES 
	if (config_setting_lookup_int(c_conf, CN_DROP_AT, &counter->drop_at) != CONFIG_TRUE) {
		RTE_LOG(ERR, COUNTER, "Could not read %s.\n", CN_DROP_AT);
		return 1;
	}

	// LOG RING SIZE
	unsigned log_ring_size;
	if (config_setting_lookup_int(c_conf, CN_RING_SIZE_LOG, &log_ring_size) != CONFIG_TRUE) {
		RTE_LOG(ERR, COUNTER, "Could not read %s.\n", CN_RING_SIZE_LOG);
		return 1;
	}
	if (log_ring_size > 31) {
		RTE_LOG(ERR, COUNTER, "Ring size to big!");
	}

	// SHOULD ENCAP ON REGISTER
	int should_encap;
	if (config_setting_lookup_bool(c_conf, CN_ENCAP_ON_REGISTER, &should_encap) != CONFIG_TRUE) {
		RTE_LOG(ERR, COUNTER, "Could not read %s.\n", CN_ENCAP_ON_REGISTER);
		return 1;
	}
	counter->encap_on_register = (bool) should_encap;

	// INIT RING
	counter->ring = rte_ring_create("counter_ring",
									(1 << log_ring_size),
									SOCKET_ID_ANY,
									RING_F_SC_DEQ | RING_F_SP_ENQ);	
	switch((uint64_t) counter->ring) {
		case E_RTE_NO_CONFIG:
			RTE_LOG(ERR, COUNTER, "Init ring failed: could not get pointer to rte_config structure");
			return 1;
		case E_RTE_SECONDARY:
			RTE_LOG(ERR, COUNTER, "Init ring failed: called from a secondary process instance");
			return 1;
		case EINVAL:
			RTE_LOG(ERR, COUNTER, "Init ring failed: count provided is not a power of 2");
			return 1;
		case ENOSPC:
			RTE_LOG(ERR, COUNTER, "Init ring failed: the maximum number of memzones has already been allocated");
			return 1;
		case EEXIST:
			RTE_LOG(ERR, COUNTER, "Init ring failed: a memzone with the same name already exists");
			return 1;
		case ENOMEM:
			RTE_LOG(ERR, COUNTER, "Init ring failed: no appropriate memory area found in which to create memzone");
			return 1;
	}

	counter->pkts_received = 0;
	counter->pkts_send = 0;
	counter->pool = appconfig->mempool;
	
	return 0;
}

