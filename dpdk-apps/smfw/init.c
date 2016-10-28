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

#include <rte_malloc.h>
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

#define MBUF_SIZE RTE_MBUF_DEFAULT_BUF_SIZE

#define NB_RXD RTE_TEST_RX_DESC_DEFAULT
#define NB_TXD RTE_TEST_TX_DESC_DEFAULT

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
	sprintf(name, "mbufpkt_pool_%i", rand());
	
	struct rte_mempool *pktmbuf_pool = rte_pktmbuf_pool_create(name, size, 32,
										0, MBUF_SIZE, rte_socket_id());
	if (pktmbuf_pool == NULL) {
		RTE_LOG(ERR, MEM_INIT, "Mempool Creation Failed. Enough memory?\n");
		die();
	}
	return pktmbuf_pool;
}

struct rte_mempool *
create_clone_pool(unsigned size) {
	RTE_LOG(INFO, MEM_INIT, "Create mempool %"PRIu32"\n", size);
	char name[128];
	sprintf(name, "mbufclone_pool_%i", rand());
	
	struct rte_mempool *clone_pool = rte_pktmbuf_pool_create(name, size, 32,
                0, 0, rte_socket_id());

	if (clone_pool == NULL) {
		RTE_LOG(ERR, MEM_INIT, "Mempool Creation Failed. Enough memory?\n");
		die();
	}
	return clone_pool;
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
		int rx_setup = rte_eth_rx_queue_setup(portid, i, NB_RXD,
			rte_eth_dev_socket_id(portid), NULL, mempool);
		if (rx_setup < 0) {
			RTE_LOG(INFO, PORT_INIT, "rx setup ERROR %d\n", rx_setup);
			return 1;
		}
	}
	
	// Initialize TX-queues for each port.
	struct rte_eth_txconf *txconf = &dev_info.default_txconf;
	txconf->txq_flags = 0;
	for (unsigned i = 0; i < tx_queues; i++) {
		fflush(stdout);
		int tx_setup = rte_eth_tx_queue_setup(portid, i, NB_TXD,
			rte_eth_dev_socket_id(portid), txconf);
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
	
	rte_eth_promiscuous_enable(portid);
	
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
	rte_free(config);
}

static int
read_core_config(struct app_config * appconfig, config_t * config, struct core_config * core_configs) {

	if (appconfig->nb_cores != rte_lcore_count()) {
		RTE_LOG(ERR, CONFIG, "lcore count is unequal to core count in config."
				" in config: %"PRIu32" but got: %"PRIu32".\n", appconfig->nb_cores, rte_lcore_count());
		config_destroy(config);
		rte_free(config);
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
		RTE_LOG(INFO, CONFIG, "No forwarder.\n");
		return 0;
	}

	// get number of configured forwarder and allocate memory for a pointer array in app_config
	appconfig->nb_forwarder = config_setting_length(forwarders_conf);
	RTE_LOG(INFO, CONFIG, "Allocate memory for %"PRIu32" forwarder.\n", appconfig->nb_forwarder);

	// memory for array of forwarder pointer
	appconfig->forwarder = rte_malloc(NULL, sizeof(struct forwarder_t*)
									 * appconfig->nb_forwarder, 64);

	// init forwarder and add it to the forwarder array in app_config
	for (unsigned i = 0; i < appconfig->nb_forwarder; ++i) {
		config_setting_t * f_conf = config_setting_get_elem(forwarders_conf, i);

		struct forwarder_t *forwarder = rte_malloc(NULL, sizeof(struct forwarder_t), 64);
		RTE_LOG(INFO, CONFIG, "New forwarder!\n");

		if (get_forwarder(f_conf, appconfig, forwarder) != 0) {
			RTE_LOG(ERR, CONFIG, "Could not set up forwarder.\n");
			config_destroy(config);
			rte_free(config);
			rte_free(forwarder);
			rte_free(appconfig->forwarder);
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
	appconfig->counter = rte_malloc(NULL, sizeof(struct counter_t*)
									 * appconfig->nb_counter, 64);

	// memory for core config
	for (unsigned i = 0; i < appconfig->nb_cores; i++) {
		core_configs[i].counter = rte_malloc(NULL, sizeof(void *) * appconfig->nb_counter, 64);
		core_configs[i].nb_counter = 0;
	}


	// init counter and add it to the counter array in app_config
	for (unsigned i = 0; i < appconfig->nb_counter; ++i) {
		config_setting_t * f_conf = config_setting_get_elem(counters_conf, i);

		struct counter_t *counter = rte_malloc(NULL, sizeof(struct counter_t), 64);
		RTE_LOG(INFO, CONFIG, "New counter!\n");

		if (get_counter(f_conf, appconfig, counter) != 0) {
			RTE_LOG(ERR, CONFIG, "Could not set up counter.\n");
			rte_free(counter);
			rte_free(appconfig->counter);
			return 1;
		}
		if (counter->core_id >= appconfig->nb_cores) {
			RTE_LOG(ERR, CONFIG, "Core ID is %"PRIu32" but got only %"PRIu32" cores.\n",
					 counter->core_id, appconfig->nb_cores);
			rte_free(counter);
			rte_free(appconfig->counter);
			return 1;
		}

		appconfig->counter[i] = counter;

		unsigned counter_i = core_configs[counter->core_id].nb_counter;
		core_configs[counter->core_id].nb_counter += 1;
		core_configs[counter->core_id].counter[counter_i] = counter;
	}
	return 0;
}

static int
read_bench_sender_config(config_t * config, struct app_config * appconfig) {

	config_setting_t * bench_senders_conf = config_lookup(config, CN_BENCH_SENDERS);
	if (bench_senders_conf == NULL) {
		appconfig->nb_bench_sender = 0;
		RTE_LOG(INFO, CONFIG, "No bench sender.\n");
		return 0;
	}
	appconfig->nb_bench_sender = config_setting_length(bench_senders_conf);
	struct core_config *core_configs = appconfig->core_configs;

	for (unsigned i = 0; i < appconfig->nb_cores; i++) {
		core_configs[i].bench_senders = rte_malloc(NULL, sizeof(void *) * appconfig->nb_bench_sender, 64);
		core_configs[i].nb_bench_sender = 0;
	}

	RTE_LOG(INFO, CONFIG, "Allocate memory for %"PRIu32" sender.\n", appconfig->nb_bench_sender);

	// memory for array of bench sender pointer
	appconfig->bench_senders = rte_malloc(NULL, sizeof(struct bench_sender_t*)
									 * appconfig->nb_bench_sender, 64);

	for (unsigned i = 0; i < appconfig->nb_bench_sender; ++i) {
		config_setting_t * bs_conf = config_setting_get_elem(bench_senders_conf, i);

		struct bench_sender_t *bs = rte_malloc(NULL, sizeof(struct bench_sender_t), 64);
		RTE_LOG(INFO, CONFIG, "New sender!\n");

		if (get_bench_sender(bs_conf, appconfig, bs) != 0) {
			RTE_LOG(ERR, CONFIG, "Could not set up bench sender.\n");
			config_destroy(config);
			rte_free(config);
			rte_free(bs);
			rte_free(appconfig->bench_senders);
			return 1;
		}

		appconfig->bench_senders[i] = bs;

		// add the new sender to the core and increment the number of sender for this core
		unsigned bs_i = core_configs[bs->core_id].nb_bench_sender;
		core_configs[bs->core_id].nb_bench_sender += 1;
		core_configs[bs->core_id].bench_senders[bs_i] = bs;
	}
	return 0;
}

static int
read_bench_receiver_config(config_t * config, struct app_config * appconfig) {

	config_setting_t * bench_receivers_conf = config_lookup(config, CN_BENCH_RECEIVERS);
	if (bench_receivers_conf == NULL) {
		appconfig->nb_bench_receiver = 0;
		RTE_LOG(INFO, CONFIG, "No bench receiver.\n");
		return 0;
	}

	appconfig->nb_bench_receiver = config_setting_length(bench_receivers_conf);
	struct core_config *core_configs = appconfig->core_configs;

	for (unsigned i = 0; i < appconfig->nb_cores; i++) {
		core_configs[i].bench_receivers = rte_malloc(NULL, sizeof(void *) * appconfig->nb_bench_receiver, 64);
		core_configs[i].nb_bench_receiver = 0;
	}

	RTE_LOG(INFO, CONFIG, "Allocate memory for %"PRIu32" receiver.\n", appconfig->nb_bench_receiver);

	// memory for array of bench receiver pointer
	appconfig->bench_receivers = rte_malloc(NULL, sizeof(struct bench_receiver_t*)
									 * appconfig->nb_bench_receiver, 64);

	for (unsigned i = 0; i < appconfig->nb_bench_receiver; ++i) {
		config_setting_t *br_conf = config_setting_get_elem(bench_receivers_conf, i);

		struct bench_receiver_t *br = rte_malloc(NULL, sizeof(struct bench_receiver_t), 64);
		RTE_LOG(INFO, CONFIG, "New receiver!\n");

		if (get_bench_receiver(br_conf, appconfig, br) != 0) {
			RTE_LOG(ERR, CONFIG, "Could not set up bench receiver.\n");
			config_destroy(config);
			rte_free(config);
			rte_free(br);
			rte_free(appconfig->bench_receivers);
			return 1;
		}

		appconfig->bench_receivers[i] = br;
	}
	return 0;
}

static int
read_arp_sender_config(config_t * config, struct app_config * appconfig) {

	config_setting_t * arp_sender_conf = config_lookup(config, CN_ARP_SENDERS);
	if (arp_sender_conf == NULL) {
		appconfig->nb_arp_sender = 0;
		RTE_LOG(INFO, CONFIG, "No arp sender.\n");
		return 0;
	}

	appconfig->nb_arp_sender = config_setting_length(arp_sender_conf);
	struct core_config *core_configs = appconfig->core_configs;

	for (unsigned i = 0; i < appconfig->nb_cores; i++) {
		core_configs[i].arp_senders = rte_malloc(NULL, sizeof(void *) * appconfig->nb_arp_sender, 64);
		core_configs[i].nb_arp_sender = 0;
	}

	RTE_LOG(INFO, CONFIG, "Allocate memory for %"PRIu32" arp sender.\n", appconfig->nb_arp_sender);

	// memory for array of arp sender pointer
	appconfig->arp_senders = rte_malloc(NULL, sizeof(struct arp_sender_t*)
									 * appconfig->nb_arp_sender, 64);

	for (unsigned i = 0; i < appconfig->nb_arp_sender; ++i) {
		config_setting_t *sett = config_setting_get_elem(arp_sender_conf, i);

		struct arp_sender_t *as = rte_malloc(NULL, sizeof(struct arp_sender_t), 64);
		RTE_LOG(INFO, CONFIG, "New arp sender!\n");

		if (get_arp_sender(sett, appconfig, as) != 0) {
			RTE_LOG(ERR, CONFIG, "Could not set up arp sender.\n");
			config_destroy(config);
			rte_free(config);
			rte_free(as);
			rte_free(appconfig->arp_senders);
			return 1;
		}

		appconfig->arp_senders[i] = as;
	}
	return 0;
}

int
read_config(const char * file, struct app_config * appconfig) {
	RTE_LOG(INFO, CONFIG, "read config file: %s\n", file);


	config_t * config = rte_malloc(NULL, sizeof(config_t), 64);
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
	appconfig->pkt_pool = create_pool((1 << pool_size) - 1);
	appconfig->clone_pool = create_clone_pool((1 << pool_size) - 1);

	/*
	 * Port set up
	 */
	for(unsigned i = 0; i < appconfig->nb_ports; ++i) {
		if ((appconfig->enabled_ports & (1 << i)) == 0) {
			appconfig->nb_ports--;
			RTE_LOG(INFO, CONFIG, "Skipp port %"PRIu32".\n", i);
			continue;
		}
		int status = initialize_port(i, appconfig->pkt_pool, 1, 1);
		if (status != 0) {
			RTE_LOG(ERR, CONFIG, "Initialization of port %"PRIu32" failed.\n", i);
			config_destroy(config);
			rte_free(config);
			return 1;
		}
	}
	check_all_ports_link_status(appconfig->nb_ports, appconfig->enabled_ports);
	/*
	 * Core set up
	 */
	struct core_config * core_configs = rte_malloc(NULL, sizeof(struct core_config) * appconfig->nb_cores, 64);
	if (read_core_config(appconfig, config, core_configs) != 0) {
		RTE_LOG(ERR, CONFIG, "Configuration failed: could not read core config.\n");
		return 1;
	}
	for (unsigned i = 0; i < appconfig->nb_cores; ++i) {
		core_configs[i].receiver = rte_malloc(NULL, sizeof(void *) * appconfig->nb_ports, 64);
		core_configs[i].nb_receiver = 0;

	}

	/*
	 * Set up senders and receiver
	 */
	config_setting_t * receive_core_set = config_lookup(config, CN_RECEIVE_ON_CORES);

	appconfig->sender = rte_malloc(NULL, sizeof(struct transmit_t *) * appconfig->nb_ports, 64);
	appconfig->receiver = rte_malloc(NULL, sizeof(struct receiver_t *) * appconfig->nb_ports, 64);

	unsigned port_index = 0;
	for (int port_id = 0; port_id < rte_eth_dev_count(); ++port_id) {
		if ((appconfig->enabled_ports & (1 << port_id)) == 0) {
			continue;
		}

		appconfig->sender[port_index] = tx_create_immediate(port_id, 0);
		appconfig->nb_sender += 1;

		/* add receiver to app_config */
		unsigned core_id = config_setting_get_int_elem(receive_core_set, port_index);

		appconfig->receiver[port_index] = rte_malloc(NULL, sizeof(struct receiver_t), 64);
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
		rte_free(config);
		return 1;
	}

	/*
	 * Read configuration of bench sender:
	 */
	if (read_bench_sender_config(config, appconfig) != 0) {
		RTE_LOG(ERR, CONFIG, "Configuration failed: could not read bench sender.\n");
		return 1;
	}

	/*
	 * Read configuration of bench receiver:
	 */
	if (read_bench_receiver_config(config, appconfig) != 0) {
		RTE_LOG(ERR, CONFIG, "Configuration failed: could not read bench receiver.\n");
		return 1;
	}

	/*
	 * Read configuration of arp sender:
	 */
	if (read_arp_sender_config(config, appconfig) != 0) {
		RTE_LOG(ERR, CONFIG, "Configuration failed: could not read arp sender.\n");
		return 1;
	}

	/*
	 * Link receiver to componentes 
	 */

	unsigned nb_receiving_comp = appconfig->nb_forwarder + appconfig->nb_counter + appconfig->nb_bench_receiver;

	for (int receiver_i = 0; receiver_i < appconfig->nb_receiver; ++receiver_i) {
		RTE_LOG(INFO, CONFIG, "Link receiver %"PRIu32"/%"PRIu32".\n", receiver_i, appconfig->nb_receiver);
		struct receiver_t *receiver = appconfig->receiver[receiver_i];

		receiver->args = rte_malloc(NULL, sizeof(void*) * nb_receiving_comp, 64);
		receiver->handler = rte_malloc(NULL, sizeof(void*) * nb_receiving_comp, 64);

		int comp_i = 0;

		/*
		 * Link order is imoportant.
		 * counter received packets first. So he has enough time to register them.
		 * Packets are faster forwarded to the FW and received than they are registered.
		 * registation runs an an other thread.
		 */

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

		/* Link forwarder */
		for (int fwd_i = 0; fwd_i < appconfig->nb_forwarder; ++fwd_i) {
			struct forwarder_t * fwd = appconfig->forwarder[fwd_i];

			if (fwd->rx != receiver) {
				continue;
			}
			receiver->args[comp_i] = fwd;
			receiver->handler[comp_i] = forwarder_receive_pkt;
			fwd->rx = receiver;
			receiver->nb_handler += 1;

			++comp_i;
		}

		/* Link bench receiver */
		for (int bench_rec_i = 0; bench_rec_i < appconfig->nb_bench_receiver; ++bench_rec_i) {
			struct bench_receiver_t * b_receiver = appconfig->bench_receivers[bench_rec_i];

			if (b_receiver->rx != receiver) {
				continue;
			}
			receiver->args[comp_i] = b_receiver;
			receiver->handler[comp_i] = bench_receiver_receive_pkt;
			b_receiver->rx = receiver;

			receiver->nb_handler++;
			++comp_i;
		}
	}

	/*
	 * Finish the configuration, clear resources, ...
	 */
	config_destroy(config);
	rte_free(config);

	RTE_LOG(INFO, CONFIG, "Configuration finished.\n");
	return 0;
}

