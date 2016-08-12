#include "init.h"
#include "parse.h"
#include "config.h"

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


#define libconfig_int int

/*
* Configurable number of RX/TX ring descriptors
*/
#define RTE_TEST_RX_DESC_DEFAULT 128
#define RTE_TEST_TX_DESC_DEFAULT 512

#define MBUF_SIZE 2000

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
	
	char name[128];
	sprintf(name, "mbuf_pool_%i", rand());
	
	struct rte_mempool * pktmbuf_pool =
	rte_pktmbuf_pool_create(name, size, 32,
				0, MBUF_SIZE, rte_socket_id());
	if (pktmbuf_pool == NULL) {
		printf("Mempool Creation Failed. Enough memory?\n");
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
	free(config);
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
	 * core number, enabled ports,
	 * number of bench senders,
	 */

	appconfig->nb_ports = rte_eth_dev_count();

	if (config_lookup_int(config, CN_CORES, &appconfig->nb_cores) != CONFIG_TRUE ||
		config_lookup_int(config, CN_PORTMASK, &appconfig->enabled_ports) != CONFIG_TRUE) {
		RTE_LOG(ERR, CONFIG, "Could not get port mask or core number from config.\n");
		config_fail(config);
		return 1;
	}

	appconfig->mempool = create_pool(MBUF_SIZE);

	for(unsigned i = 0; i < appconfig->nb_ports; ++i) {
		if ((appconfig->enabled_ports & (1 << i)) == 0) {
			appconfig->nb_ports--;
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
	* Core Setup
	*/
	
	if (appconfig->nb_cores != rte_lcore_count()) {
		RTE_LOG(ERR, CONFIG, "lcore count is unequal to core count in config."
			    " in config: %"PRIu32" but got: %"PRIu32".\n", appconfig->nb_cores, rte_lcore_count());
		config_destroy(config);
		free(config);
		return 1;
	}
	
	unsigned core_list[appconfig->nb_cores];
	struct core_config * core_configs = malloc(sizeof(struct core_config) * appconfig->nb_cores);
	appconfig->core_configs = core_configs;
	unsigned core = rte_get_master_lcore();

	for (unsigned i = 0; i < appconfig->nb_cores; i++) {
		core_list[i] = core;
		rte_eal_wait_lcore(core);
		
		core_configs[i].core             = core;
		core_configs[i].bench_send_count = 0;
		
		core_configs[i].bench_senders = malloc(sizeof(void *) * appconfig->nb_bench_sender);
		
		if (i < appconfig->nb_cores - 1) {
			core = rte_get_next_lcore(core, 1, 1);
		}
	}


	/*
	 * Read configuration of bench sender:
	 */
	config_setting_t * bench_senders_conf = config_lookup(config, CN_BENCH_SENDERS);
	
	appconfig->nb_bench_sender = config_setting_length(bench_senders_conf);

	// memory for array of bench sender pointer
	appconfig->bench_senders = malloc(sizeof(struct bench_sender_t*)
									 * appconfig->nb_bench_sender);

	for (unsigned i = 0; i < appconfig->nb_bench_sender; ++i) {
		config_setting_t * bs_conf = config_setting_get_elem(bench_senders_conf, i);

		struct bench_sender_t *bs = malloc(sizeof(struct bench_sender_t));

		if (read_send_bench(bs_conf, appconfig->mempool, bs) != 0) {
			RTE_LOG(ERR, CONFIG, "Could not set up bench sender.\n");
			config_destroy(config);
			free(config);
			free(bs);
			free(appconfig->bench_senders);
			return 1;
		}

		appconfig->bench_senders[i] = bs;

		unsigned bs_i = core_configs[bs->core_id].bench_send_count;
		core_configs[bs->core_id].bench_send_count += 1;
		core_configs[bs->core_id].bench_senders[bs_i] = bs;
	}

	config_destroy(config);
	free(config);

	RTE_LOG(INFO, CONFIG, "Configurations read.\n");
	return 0;
}

