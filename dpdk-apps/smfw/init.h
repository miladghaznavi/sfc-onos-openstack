/* 
 * Initialization of the ethernet devices.
 * Parsing of configurtaion file.
 */
#ifndef INIT_H_
#define INIT_H_

#include <libconfig.h>
#include <inttypes.h>

#include <rte_mbuf.h>

#include "components/forwarder.h"
#include "components/receiver.h"
#include "components/counter.h"
#include "components/bench_sender.h"
#include "components/bench_receiver.h"
#include "components/arp_sender.h"
#include "components/mirrow.h"

#define TRUE 1
#define FALSE 0
#define START_DEBUGGER_ON_ERROR FLASE

/**
 * Per core app config
 */
struct core_config {
	unsigned core;
	uint64_t nb_polls;
	uint64_t last_stat_used_cycles;

	unsigned nb_receiver;
	struct receiver_t **receiver;

	unsigned nb_counter;
	struct counter_t **counter;

	unsigned nb_bench_sender;
	struct bench_sender_t **bench_senders;

	unsigned nb_bench_receiver;
	struct bench_receiver_t **bench_receivers;

	unsigned nb_arp_sender;
	struct arp_sender_t **arp_senders;

	unsigned nb_mirrow;
	struct mirrow_t **mirrows;
};

/**
 * Global app config
 */
struct app_config {
	unsigned nb_ports;
	unsigned enabled_ports;

	struct rte_mempool *pkt_pool;
	struct rte_mempool *clone_pool;

	// CORE Comps

	unsigned nb_cores;
	struct core_config *core_configs;

	unsigned nb_sender;
	struct transmit_t **sender;

	unsigned nb_receiver;
	struct receiver_t **receiver;

	// FIREWALL Comps

	unsigned nb_forwarder;
	struct forwarder_t **forwarder;

	unsigned nb_counter;
	struct counter_t **counter;

	// BENCH Comps

	unsigned nb_bench_sender;
	struct bench_sender_t   **bench_senders;

	unsigned nb_bench_receiver;
	struct bench_receiver_t **bench_receivers;

	// HELPER Comps

	unsigned nb_arp_sender;
	struct arp_sender_t **arp_senders;

	unsigned nb_mirrow;
	struct mirrow_t **mirrow;
};

/**
 * Aborts the application.
 * 
 * If START_DEBUGGER_ON_ERROR is TRUE, this spawns a gdb instance
 * and attaches it to the program before carshing the app to get into the debugger.
 */
void
die(void);

int
initialize_port(uint8_t portid, struct rte_mempool* mempool, 
				uint16_t rx_queues, uint16_t tx_queues);

struct rte_mempool *
create_pool(unsigned size);

/**
* Check the link status of all ports in up to 9 seconds, and print them
* finally.
*/
void
check_all_ports_link_status(uint8_t port_num, uint32_t port_mask);

/**
 * Read the config file.
 * Creates all Replicator, Comparator (aka Votecounter), Wrapper and Loadgen structures.
 * Setup the app_config and core_config structures.
 * This functions really needs some modularization.
 *
 * @param[in] file
 *   filename of file to read config from
 * @param[out] appconfig
 *   a pointer to empty app_config struct. The struct will contain the read configs.
 * @return
 *   0 on success, 1 otherwise.
 */
int
read_config(const char * file, struct app_config * appconfig);

/**
 * Gets the standard transmit structure for the given port
 */
struct transmit_t *
get_tx(unsigned port);

#endif /* INIT_H_ */
