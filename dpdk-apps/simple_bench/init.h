/* 
 * Initialization of the ethernet devices.
 * Parsing of configurtaion file.
 */
#ifndef INIT_H_
#define INIT_H_

#include "bench_sender.h"

#define TRUE 1
#define FALSE 0
#define START_DEBUGGER_ON_ERROR TRUE

/**
 * Per core app config
 */
struct core_config {
    unsigned core;

    unsigned bench_send_count;
    struct bench_sender_t ** bench_senders;

    // unsigned bench_fwd_count;
    // struct bench_fwd_t ** bench_fwders;

    // unsigned bench_receive_count;
    // struct bench_receive_t ** bench_receivers;


    uint64_t nb_polls;
};

/**
 * Global app config
 */
struct app_config {
    unsigned nb_ports;
    unsigned nb_cores;

    unsigned enabled_ports;

    unsigned nb_bench_sender;
    // unsigned nb_bench_fwd;
    // unsigned nb_bench_receive;

    struct rte_mempool       *mempool;
    struct transmit_t       **tx_port_rings;
    struct core_config       *core_configs;

    struct bench_sender_t   **bench_senders;
    // struct votecounter_t    ** votecounters;
    // struct wrapper_worker_t ** wrappers;
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
