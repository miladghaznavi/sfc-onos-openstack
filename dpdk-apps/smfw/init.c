#include "init.h"
#include "parse.h"
#include "config.h"
#include "rxtx.h"

#include <getopt.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <libconfig.h>

#include <rte_common.h>
#include <rte_cycles.h>
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_mbuf.h>
#include <rte_mempool.h>
#include <rte_errno.h>
#include <rte_log.h>

#define RTE_LOGTYPE_CONFIG RTE_LOGTYPE_USER1
#define RTE_LOGTYPE_PORT_INIT RTE_LOGTYPE_USER2
#define RTE_LOGTYPE_MEM_INIT RTE_LOGTYPE_USER3


#define libconfig_int int

/*
* Configurable number of RX/TX ring descriptors
*/
#define RTE_TEST_RX_DESC_DEFAULT 128
#define RTE_TEST_TX_DESC_DEFAULT 512

static uint16_t nb_rxd = RTE_TEST_RX_DESC_DEFAULT;
static uint16_t nb_txd = RTE_TEST_TX_DESC_DEFAULT;

/**
* Ethernet addresses of ports.
*/
static struct ether_addr ports_eth_addr[RTE_MAX_ETHPORTS];

static const struct rte_eth_conf port_conf = {
	.rxmode = {
		.split_hdr_size = 0,
		.header_split   = 0, /**< Header Split disabled */
		.hw_ip_checksum = 0, /**< IP checksum offload disabled */
		.hw_vlan_filter = 0, /**< VLAN filtering disabled */
		.jumbo_frame    = 0, /**< Jumbo Frame Support disabled */
		.hw_strip_crc   = 0, /**< CRC stripped by hardware */
	},
	.txmode = {
		.mq_mode = ETH_MQ_TX_VMDQ_ONLY,
	},
};

void
die(void) {
#if START_DEBUGGER_ON_ERROR == TRUE
	int eno = rte_errno;
	const char * errstr = rte_strerror(eno);
	printf("\n\nEXIT. ERRNO: %s (%i)\n\n", errstr, eno);
	char pidstr[128];
	sprintf(pidstr, "%i", getpid());

	if (vfork() == 0) {
		execl("/usr/bin/gdb", "gdb", "-p", pidstr,(char *) 0);
	}
	sleep(2);

	int x = *((int *) NULL);
#endif

	rte_exit(1, "exit");
}

void
check_all_ports_link_status(uint8_t port_num, uint32_t port_mask)
{
	#define CHECK_INTERVAL 100 /* 100ms */
	#define MAX_CHECK_TIME 90 /* 9s (90 * 100ms) in total */
	uint8_t portid, count, all_ports_up, print_flag = 0;
	struct rte_eth_link link;
	
	printf("Checking link status");
	
	for (count = 0; count <= MAX_CHECK_TIME; count++) {
		all_ports_up = 1;
		for (portid = 0; portid < port_num; portid++) {
			if ((port_mask & (1 << portid)) == 0) continue;
			memset(&link, 0, sizeof(link));
			rte_eth_link_get_nowait(portid, &link);
			// Print link status if flag set.
			if (print_flag == 1) {
				if (link.link_status) {
					printf("  Port %d Link Up - speed %u "
						"Mbps - %s\n", (uint8_t)portid,
						(unsigned)link.link_speed,
						(link.link_duplex == ETH_LINK_FULL_DUPLEX) ?
						("full-duplex") : ("half-duplex\n"));
				} else {
					printf("Port %d DOWN\n", (uint8_t) portid);
				}
				continue;
			}
			// Clear all_ports_up flag if any link down.
			if (link.link_status == 0) {
			all_ports_up = 0;
			break;
			}
		}
		// After finally printing all link status, get out.
		if (print_flag == 1)
			break;
		
		if (all_ports_up == 0) {
			printf(".");
			fflush(stdout);
			rte_delay_ms(CHECK_INTERVAL);
		}
		
		// Set the print_flag if all ports up or timeout.
		if (all_ports_up == 1 || count == (MAX_CHECK_TIME - 1)) {
			print_flag = 1;
			printf("OK");
		}
	}
}

struct rte_mempool *
create_pool(unsigned size) {
	RTE_LOG(INFO, MEM_INIT, "Create mempool %"PRIu32"\n", size);
	char name[128];
	sprintf(name, "mbuf_pool_%i", rand());
	
	struct rte_mempool *pktmbuf_pool = rte_pktmbuf_pool_create(name, size, 32,
										0, size, rte_socket_id());
	if (pktmbuf_pool == NULL) {
		RTE_LOG(ERR, MEM_INIT, "Mempool Creation Failed. Enough memory?\n");
		die();
	}
	return pktmbuf_pool;
}

int
initialize_port(uint8_t portid, struct rte_mempool* mempool, uint16_t rx_queues, uint16_t tx_queues) {
	// Get the device information.
	struct rte_eth_dev_info dev_info;
	rte_eth_dev_info_get(portid, &dev_info);
	
	// Initialize the port.
	RTE_LOG(INFO, PORT_INIT, "Initializing port %u\n", (unsigned) portid);
	int configured = rte_eth_dev_configure(portid, rx_queues, tx_queues, &port_conf);
	if (configured < 0) {
		RTE_LOG(INFO, PORT_INIT, "configure ERROR %d\n", configured);
		return 1;
	}
	
	rte_eth_macaddr_get(portid, &ports_eth_addr[portid]);
	
	// Initialize RX-queues for each port.
	for (unsigned i = 0; i < rx_queues; i++) {
		fflush(stdout);
		int rx_setup = rte_eth_rx_queue_setup(portid, i, nb_rxd,
			rte_eth_dev_socket_id(portid), NULL, mempool);
		if (rx_setup < 0) {
			RTE_LOG(INFO, PORT_INIT, "rx setup ERROR %d\n", rx_setup);
			return 1;
		}
	}
	
	// Initialize TX-queues for each port.
	for (unsigned i = 0; i < tx_queues; i++) {
		fflush(stdout);
		int tx_setup = rte_eth_tx_queue_setup(portid, i, nb_txd,
			rte_eth_dev_socket_id(portid), NULL);
		if (tx_setup < 0) {
			RTE_LOG(INFO, PORT_INIT, "tx setup ERROR %d\n", tx_setup);
			return 1;
		}
	}
	
	// Start the device.
	int started = rte_eth_dev_start(portid);
	if (started < 0) {
		RTE_LOG(INFO, PORT_INIT, "start ERROR %d\n", started);
		return 1;
	}
	
	// rte_eth_promiscuous_enable(portid);
	
	RTE_LOG(INFO, PORT_INIT, "OK, MAC: %02X:%02X:%02X:%02X:%02X:%02X\n",
		ports_eth_addr[portid].addr_bytes[0],
		ports_eth_addr[portid].addr_bytes[1],
		ports_eth_addr[portid].addr_bytes[2],
		ports_eth_addr[portid].addr_bytes[3],
		ports_eth_addr[portid].addr_bytes[4],
		ports_eth_addr[portid].addr_bytes[5]);
	
	return 0;
}

static void
config_fail(config_t * config) {
	RTE_LOG(ERR, CONFIG, "Could not read config file: \n\tLine %i : %s\n",
	config_error_line(config), config_error_text(config));
	config_destroy(config);
	free(config);
}

static int
read_core_config(struct app_config * appconfig, config_t * config, struct core_config * core_configs) {

	if (appconfig->nb_cores != rte_lcore_count()) {
		RTE_LOG(ERR, CONFIG, "lcore count is unequal to core count in config."
			    " in config: %"PRIu32" but got: %"PRIu32".\n", appconfig->nb_cores, rte_lcore_count());
		config_destroy(config);
		free(config);
		return 1;
	}
	
	unsigned core_list[appconfig->nb_cores];
	appconfig->core_configs = core_configs;

	unsigned core = rte_get_master_lcore();

	for (unsigned i = 0; i < appconfig->nb_cores; i++) {
		core_list[i] = core;
		rte_eal_wait_lcore(core);
		
		core_configs[i].core = core;
		// core_configs[i].nb_sender = 0;
		
		
		if (i < appconfig->nb_cores - 1) {
			core = rte_get_next_lcore(core, 1, 1);
		}
	}

	return 0;
}

static int
read_forwarder_config(config_t *config, struct app_config *appconfig) {

	// get and check config
	config_setting_t *forwarders_conf = config_lookup(config, CN_FORWARDERS);
	if (forwarders_conf == NULL) {
		appconfig->nb_forwarder = 0;
		RTE_LOG(INFO, CONFIG, "No forwarder.");
		return 0;
	}

	// get number of configured forwarder and allocate memory for a pointer array in app_config
	appconfig->nb_forwarder = config_setting_length(forwarders_conf);
	RTE_LOG(INFO, CONFIG, "Allocate memory for %"PRIu32" forwarder.\n", appconfig->nb_forwarder);

	// memory for array of forwarder pointer
	appconfig->forwarder = malloc(sizeof(struct forwarder_t*)
									 * appconfig->nb_forwarder);

	// init forwarder and add it to the forwarder array in app_config
	for (unsigned i = 0; i < appconfig->nb_forwarder; ++i) {
		config_setting_t * f_conf = config_setting_get_elem(forwarders_conf, i);

		struct forwarder_t *forwarder = malloc(sizeof(struct forwarder_t));
		RTE_LOG(INFO, CONFIG, "New forwarder!\n");

		if (get_forwarder(f_conf, appconfig, forwarder) != 0) {
			RTE_LOG(ERR, CONFIG, "Could not set up forwarder.\n");
			config_destroy(config);
			free(config);
			free(forwarder);
			free(appconfig->forwarder);
			return 1;
		}

		appconfig->forwarder[i] = forwarder;
	}
	return 0;
}

static int
read_counter_config(config_t *config, struct app_config *appconfig) {

	struct core_config *core_configs = appconfig->core_configs;

	// get and check config
	config_setting_t *counters_conf = config_lookup(config, CN_COUNTER);
	if (counters_conf == NULL) {
		for (unsigned i = 0; i < appconfig->nb_cores; i++) {
			core_configs[i].nb_counter = 0;
		}
		appconfig->nb_counter = 0;
		RTE_LOG(INFO, CONFIG, "No counter.\n");
		return 0;
	}

	// get number of configured counter and allocate memory for a pointer array in app_config
	appconfig->nb_counter = config_setting_length(counters_conf);
	RTE_LOG(INFO, CONFIG, "Allocate memory for %"PRIu32" counter.\n", appconfig->nb_counter);

	// memory for array of counter pointer
	appconfig->counter = malloc(sizeof(struct counter_t*)
									 * appconfig->nb_counter);

	// memory for core config
	for (unsigned i = 0; i < appconfig->nb_cores; i++) {
		core_configs[i].counter = malloc(sizeof(void *) * appconfig->nb_counter);
		core_configs[i].nb_counter = 0;
	}


	// init counter and add it to the counter array in app_config
	for (unsigned i = 0; i < appconfig->nb_counter; ++i) {
		config_setting_t * f_conf = config_setting_get_elem(counters_conf, i);

		struct counter_t *counter = malloc(sizeof(struct counter_t));
		RTE_LOG(INFO, CONFIG, "New counter!\n");

		if (get_counter(f_conf, appconfig, counter) != 0) {
			RTE_LOG(ERR, CONFIG, "Could not set up counter.\n");
			free(counter);
			free(appconfig->counter);
			return 1;
		}
		if (counter->core_id >= appconfig->nb_cores) {
			RTE_LOG(ERR, CONFIG, "Core ID is %"PRIu32" but got only %"PRIu32" cores.\n",
					 counter->core_id, appconfig->nb_cores);
			free(counter);
			free(appconfig->counter);
			return 1;
		}

		appconfig->counter[i] = counter;

		unsigned counter_i = core_configs[counter->core_id].nb_counter;
		core_configs[counter->core_id].nb_counter += 1;
		core_configs[counter->core_id].counter[counter_i] = counter;
	}
	return 0;
}

int
read_config(const char * file, struct app_config * appconfig) {
	RTE_LOG(INFO, CONFIG, "read config file: %s\n", file);


	config_t * config = malloc(sizeof(config_t));
	config_init(config);

	if (config_read_file(config, file) != CONFIG_TRUE) {
		config_fail(config);
		return 1;
	}

	/*
	 * Read global configurations:
	 * core number, enabled ports, number of ethernet devices
	 * init mbuf pool
	 * initialize ethernet ports
	 */
	appconfig->nb_receiver = 0;
	appconfig->nb_cores = 0;
	appconfig->nb_sender = 0;
	appconfig->nb_forwarder = 0;
	appconfig->nb_ports = rte_eth_dev_count();
	RTE_LOG(INFO, CONFIG, "Got %"PRIu32" ports.\n", appconfig->nb_ports);

	if (config_lookup_int(config, CN_CORES, &appconfig->nb_cores) != CONFIG_TRUE ||
		config_lookup_int(config, CN_PORTMASK, &appconfig->enabled_ports) != CONFIG_TRUE) {
		RTE_LOG(ERR, CONFIG, "Could not get port mask or core number from config.\n");
		config_fail(config);
		return 1;
	}

	RTE_LOG(INFO, CONFIG, "Portmask is: %"PRIu32".\n", appconfig->enabled_ports);

	unsigned pool_size;
	if (config_lookup_int(config, CN_LOG_POOL_SIZE, &pool_size) != CONFIG_TRUE) {
		RTE_LOG(ERR, CONFIG, "Could not read %s.\n", CN_LOG_POOL_SIZE);
		return 1;
	}
	appconfig->mempool = create_pool((1 << pool_size) - 1);

	/*
	 * Port set up
	 */
	for(unsigned i = 0; i < appconfig->nb_ports; ++i) {
		if ((appconfig->enabled_ports & (1 << i)) == 0) {
			appconfig->nb_ports--;
			RTE_LOG(INFO, CONFIG, "Skipp port %"PRIu32".\n", i);
			continue;
		}
		int status = initialize_port(i, appconfig->mempool, 1, 1);
		if (status != 0) {
			RTE_LOG(ERR, CONFIG, "Initialization of port %"PRIu32" failed.\n", i);
			config_destroy(config);
			free(config);
			return 1;
		}
	}

	/*
	 * Core set up
	 */
	struct core_config * core_configs = malloc(sizeof(struct core_config) * appconfig->nb_cores);
	if (read_core_config(appconfig, config, core_configs) != 0) {
		RTE_LOG(ERR, CONFIG, "Configuration failed: could not read core config.\n");
		return 1;
	}
	for (unsigned i = 0; i < appconfig->nb_cores; ++i) {
		core_configs[i].receiver = malloc(sizeof(void *) * appconfig->nb_ports);
		core_configs[i].nb_receiver = 0;

	}

	/*
	 * Set up senders and receiver
	 */
	config_setting_t * receive_core_set = config_lookup(config, CN_RECEIVE_ON_CORES);

	appconfig->sender = malloc(sizeof(struct transmit_t *) * appconfig->nb_ports);
	appconfig->receiver = malloc(sizeof(struct receiver_t *) * appconfig->nb_ports);

	unsigned port_index = 0;
	for (int port_id = 0; port_id < rte_eth_dev_count(); ++port_id) {
		if ((appconfig->enabled_ports & (1 << port_id)) == 0) {
			continue;
		}

		appconfig->sender[port_index] = tx_create_immediate(port_id, 0);
		appconfig->nb_sender += 1;

		/* add receiver to app_config */
		unsigned core_id = config_setting_get_int_elem(receive_core_set, port_index);

		appconfig->receiver[port_index] = malloc(sizeof(struct receiver_t));
		init_receiver(core_id, port_id, appconfig->receiver[port_index]);
		appconfig->nb_receiver += 1;

		/* get core_id of receiver, index in core_config.receiver and add it to the core_config */
		unsigned receiver_i = core_configs[core_id].nb_receiver;
		core_configs[core_id].receiver[receiver_i] = appconfig->receiver[port_index];
		core_configs[core_id].nb_receiver += 1;


		port_index += 1;
	}

	/*
	 * Read configuration of forwarder:
	 */
	if (read_forwarder_config(config, appconfig) != 0) {
		RTE_LOG(ERR, CONFIG, "Configuration failed: could not read forwarder.\n");
		return 1;
	}

	/*
	 * Read configuration of counter:
	 */
	if (read_counter_config(config, appconfig) != 0) {
		RTE_LOG(ERR, CONFIG, "Configuration failed: could not read forwarder.\n");
		config_destroy(config);
		free(config);
		return 1;
	}

	/* Link receiver to componentes */

	unsigned nb_receiving_comp = appconfig->nb_forwarder + appconfig->nb_counter;

	for (int receiver_i = 0; receiver_i < appconfig->nb_receiver; ++receiver_i) {
		RTE_LOG(INFO, CONFIG, "Link receiver %"PRIu32"/%"PRIu32".\n", receiver_i, appconfig->nb_receiver);
		struct receiver_t *receiver = appconfig->receiver[receiver_i];

		receiver->args = malloc(sizeof(void*) * nb_receiving_comp);
		receiver->handler = malloc(sizeof(void*) * nb_receiving_comp);

		int comp_i = 0;

		/* Link forwarder */
		for (int fwd_i = 0; fwd_i < appconfig->nb_forwarder; ++fwd_i) {
			struct forwarder_t * fwd = appconfig->forwarder[fwd_i];
			// pointing to the same receiver!?
			if (fwd->rx != receiver) {
				continue;
			}
			receiver->args[comp_i] = fwd;
			receiver->handler[comp_i] = forwarder_receive_pkt;
			fwd->rx = receiver;
			receiver->nb_handler += 1;

			++comp_i;
		}

		/* Link counter */
		for (int cntr_i = 0; cntr_i < appconfig->nb_counter; ++cntr_i) {
			struct counter_t * cntr = appconfig->counter[cntr_i];
			// pointing to the same receiver!?
			if (cntr->rx_register == receiver) {
				receiver->args[comp_i] = cntr;
				receiver->handler[comp_i] = counter_register_pkt;
				receiver->nb_handler += 1;
				comp_i += 1;
			}
			if (cntr->rx_firewall == receiver) {
				receiver->args[comp_i] = cntr;
				receiver->handler[comp_i] = counter_firewall_pkt;
				receiver->nb_handler += 1;
				comp_i += 1;
			}
		}
	}
	/*
	 * Finish the configuration, clear resources, ...
	 */
	config_destroy(config);
	free(config);

	RTE_LOG(INFO, CONFIG, "Configuration finished.\n");
	return 0;
}

