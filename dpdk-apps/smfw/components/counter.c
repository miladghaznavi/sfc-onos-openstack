#include "counter.h"

#include "../config.h"
#include "../rxtx.h"
#include "../parse.h"
#include "../init.h"
#include "../indextable.h"
#include "../d_list.h"
#include "wrapping.h"

#include <stdlib.h>

#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_log.h>
#include <rte_ring.h>
#include <rte_errno.h>
#include <rte_hash_crc.h>
#include <rte_mempool.h>

#define RTE_LOGTYPE_COUNTER RTE_LOGTYPE_USER1
#define BUFFER_SIZE 32
#define BUCKET_SIZE 10000
#define ENTRIE_PER_BUCKET 4


static void
fwd_to_wrapper(struct counter_t *counter, struct rte_mbuf *m, struct metadata_t *meta) {
	struct ether_hdr *eth = rte_pktmbuf_mtod(m, struct ether_hdr *);

	ether_addr_copy(&counter->next_mac, &eth->d_addr);
	if (!counter->decap_on_send) {
		wrapper_add_data(m, meta);
	}
	int send = tx_put(counter->tx, &m, 1);
	while (send == 0) {
		send = tx_put(counter->tx, &m, 1);
	}
	counter->pkts_send += send;
	counter->nb_mbuf--;
}

static void
fwd_timedout_pkts(struct counter_t *counter) {
	struct indextable_entry *entry = indextable_oldest(counter->indextable);
	uint64_t age;

	while (entry != NULL && (age = indextable_entry_age(entry)) > counter->timeout) {
		fwd_to_wrapper(counter, entry->packet, &entry->meta);
		indextable_delete(counter->indextable, entry);
		counter->pkts_timedout += 1;
		entry = indextable_oldest(counter->indextable);
	}
}

static int
count_decissions(uint32_t decissions) {
	unsigned count = 0;
	while (decissions > 0) {
		if ((decissions & 1) == 1) ++count;
		decissions >>= 1;
	}
	return count;
}

static struct indextable_entry *
counter_register(struct counter_t *counter, struct rte_mbuf *packet) {

	struct ether_hdr *eth = rte_pktmbuf_mtod(packet, struct ether_hdr *);

	struct metadata_t metadata;
 	if (counter->encap_on_register) {
		metadata.decissions = 0;
	} else {
		metadata = *wrapper_get_data(packet);
		wrapper_remove_data(packet);
	}

	struct indextable_entry *entry = indextable_put(counter->indextable, packet);
	entry->meta = metadata;

	return entry;
}

void
counter_register_pkt(void *arg, struct rte_mbuf **buffer, int nb_rx) {
	if (nb_rx == 0) return;
	struct counter_t *counter = (struct counter_t *) arg;

	if (nb_rx > rte_ring_free_count(counter->ring)) {
		RTE_LOG(ERR, COUNTER, "Not enough free entries in ring!\n");
	}

	// enqueue packet in ring
	// this methode must be thread safe
	counter->pkts_received_r += nb_rx;
	struct rte_mbuf *bulk[nb_rx];

	unsigned nb_registered = 0;
	for (unsigned i = 0; i < nb_rx; ++i) {

		// forwarder changes MAC...
		struct ether_hdr *eth = rte_pktmbuf_mtod(buffer[i], struct ether_hdr *);
		if (!is_same_ether_addr(&counter->rx_register->mac, &eth->d_addr)) {
			RTE_LOG(INFO, COUNTER, "register drop: "FORMAT_MAC" != "FORMAT_MAC"\n",ARG_V_MAC(counter->rx_register->mac), ARG_V_MAC(eth->d_addr));
			continue;
		}

		bulk[nb_registered] = rte_pktmbuf_clone(buffer[i], counter->clone_pool);
		counter->nb_mbuf++;

		if (bulk[nb_registered] == NULL) {
			RTE_LOG(ERR, COUNTER, "Could not clone mbuf!\n");
			counter->nb_mbuf--;
			continue;
		}
		nb_registered += 1;
	}

	int n = rte_ring_enqueue_burst(counter->ring,(void * const*) &bulk, nb_registered);
	if (n < nb_rx) {
		RTE_LOG(ERR, COUNTER, "Could not enqueue every new packtes for registration! "
							  "(%"PRIu32"/%"PRIu32") free: %"PRIu32"\n", n, nb_rx, 
							  rte_ring_free_count(counter->ring));
	}
}

void
counter_firewall_pkt(void *arg, struct rte_mbuf **buffer, int nb_rx) {
	struct counter_t *counter = (struct counter_t *) arg;
    clock_t start = clock(), diff;

	poll_counter(counter);

	counter->pkts_received_fw += nb_rx;

	// check table and send packet 
	// check if <drop_at> votes are to drop the packet
	// if yes: drop it!
	// else send it

	struct indextable_entry *entry;
	struct rte_mbuf *ok_pkt;
	struct metadata_t *meta;
	struct ether_hdr *eth;

	for (unsigned i = 0; i < nb_rx; ++i) {
		struct ether_hdr *eth = rte_pktmbuf_mtod(buffer[i], struct ether_hdr *);
		if (!is_same_ether_addr(&counter->fw_port_mac, &eth->d_addr)) {
			RTE_LOG(INFO, COUNTER, "Wrong d_MAC... "FORMAT_MAC"\n", ARG_V_MAC(eth->d_addr));
			continue;
		}
		entry = indextable_get(counter->indextable, buffer[i]);

		if (entry != NULL) {
			ok_pkt = entry->packet;
			meta = &entry->meta;
			meta->decissions |= 1 << counter->chain_index;

			int decission_count = count_decissions(meta->decissions);

			if (decission_count >= counter->drop_at) {
				fwd_to_wrapper(counter, ok_pkt, meta);
			} else {
				rte_pktmbuf_free(ok_pkt);
				counter->pkts_dropped++;
			}
			indextable_delete(counter->indextable, entry);
			counter->nb_mbuf--;

		} else {
			RTE_LOG(WARNING, COUNTER, "Received unregistered packet.\n");

			// print_packet_hex(buffer[i]);
		}
	}
	fwd_timedout_pkts(counter);
    diff = clock() - start;
    counter->time += diff * 1000.0 / CLOCKS_PER_SEC;
    counter->nb_measurements += 1;
}

//| Firewall port MAC |   send port MAC   |      dst MAC      |
void
log_counter(struct counter_t *c) {
	RTE_LOG(INFO, COUNTER, "-------------------------- Counter --------------------------\n");
	// RTE_LOG(INFO, COUNTER, "| Timeout:           %"PRIu64"\n", c->timeout);
	// RTE_LOG(INFO, COUNTER, "| Out port:          %"PRIu16"\n", c->tx->port);
	// RTE_LOG(INFO, COUNTER, "| Register port:     %"PRIu16"\n", c->rx_register->in_port);
	// RTE_LOG(INFO, COUNTER, "| Firewall port:     %"PRIu16"\n", c->rx_firewall->in_port);
	RTE_LOG(INFO, COUNTER, "| Firewall port MAC |   send port MAC   |      dst MAC      |\n");
	RTE_LOG(INFO, COUNTER, "| "FORMAT_MAC" | "FORMAT_MAC" | "FORMAT_MAC" |\n", 
		ARG_V_MAC(c->fw_port_mac), ARG_V_MAC(c->send_port_mac), ARG_V_MAC(c->next_mac));

	RTE_LOG(INFO, COUNTER, "|---------------- Packet stats ----------------\n");
	RTE_LOG(INFO, COUNTER, "| rx FW  |  rx R  |  send  | dropped | timeout | \n");
	RTE_LOG(INFO, COUNTER, "| %6"PRIu64" | %6"PRIu64" | %6"PRIu64" | %7"PRIu64" | %7"PRIu64" |\n", 
		c->pkts_received_fw, c->pkts_received_r, c->pkts_send, c->pkts_dropped, c->pkts_timedout);
	RTE_LOG(INFO, COUNTER, "| Entries replaced:  %"PRIu64"\n", c->indextable->replaced_entries);
	RTE_LOG(INFO, COUNTER, "| nb Entries:        %"PRIu32"\n", d_list_len(&c->indextable->tail)-2);
    RTE_LOG(INFO, COUNTER, "| Time:             %f\n", c->time/c->nb_measurements);
	RTE_LOG(INFO, COUNTER, "| mbufs:             %"PRIu32"\n", rte_mempool_count(c->pool));
	struct indextable_entry *entry = indextable_oldest(c->indextable);
	if (entry != NULL) {
		RTE_LOG(INFO, COUNTER, "| oldest :   %"PRIu64"\n", indextable_entry_age(entry));
	}
	RTE_LOG(INFO, COUNTER, "-------------------------------------------------------------\n");
}

void
poll_counter(struct counter_t *counter) {

	// check if ring contains new mbufs
	// register new mbufs
	struct rte_mbuf *buffer[BUFFER_SIZE];

	while (!rte_ring_empty(counter->ring)) {
		unsigned nb_pkt = rte_ring_dequeue_burst(counter->ring,(void **) &buffer, BUFFER_SIZE);
		for (unsigned i = 0; i < nb_pkt; ++i) {
			counter_register(counter, buffer[i]);
		}
	}
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
get_counter(config_setting_t *c_conf,
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
		counter->core_id = counter->rx_firewall->core_id;
	}

	// SOURCE MAC
	rte_eth_macaddr_get(counter->tx->port, &counter->send_port_mac);
	rte_eth_macaddr_get(counter->rx_firewall->in_port, &counter->fw_port_mac);

	//NEXT VNF MAC
	if (read_mac(c_conf, CN_NEXT_VNF_MAC, &counter->next_mac) != 0) {
		RTE_LOG(ERR, COUNTER, "Could not read %s.\n", CN_NEXT_VNF_MAC);
		return 1;
	}

	// Chain position
	if (config_setting_lookup_int(c_conf, CN_CHAIN_INDEX, &counter->chain_index) != CONFIG_TRUE) {
		RTE_LOG(ERR, COUNTER, "Could not read %s.\n", CN_CHAIN_INDEX);
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

	// SHOULD DECAP ON SEND
	int should_decap;
	if (config_setting_lookup_bool(c_conf, CN_DECAP_ON_SEND, &should_decap) != CONFIG_TRUE) {
		RTE_LOG(ERR, COUNTER, "Could not read %s.\n", CN_DECAP_ON_SEND);
		return 1;
	}
	counter->decap_on_send = (bool) should_decap;

	// TIMEOUT
	int timeout;
	if (config_setting_lookup_int(c_conf, CN_TIMEOUT, &timeout) != CONFIG_TRUE) {
		RTE_LOG(ERR, COUNTER, "Could not read %s.\n", CN_TIMEOUT);
		return 1;
	}
	counter->timeout = timeout;

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

	unsigned table_size;
	if (config_setting_lookup_int(c_conf, CN_TABLE_SIZE, &table_size) != CONFIG_TRUE) {
		RTE_LOG(ERR, COUNTER, "Could not read %s.\n", CN_TABLE_SIZE);
		return 1;
	}

	unsigned bucket_per_entry;
	if (config_setting_lookup_int(c_conf, CN_BUCKET_PER_ENTRY, &bucket_per_entry) != CONFIG_TRUE) {
		RTE_LOG(ERR, COUNTER, "Could not read %s.\n", CN_BUCKET_PER_ENTRY);
		return 1;
	}

	counter->indextable = indextable_create(table_size, bucket_per_entry);

	counter->pkts_received_fw = 0;
	counter->pkts_received_r = 0;
	counter->pkts_send = 0;
	counter->pkts_dropped = 0;
	counter->pkts_timedout = 0;
	counter->pool = appconfig->pkt_pool;
	counter->clone_pool = appconfig->clone_pool;
	counter->nb_mbuf = 0;
    counter->time = 0.0;
    counter->nb_measurements = 0.0;

	return 0;
}
