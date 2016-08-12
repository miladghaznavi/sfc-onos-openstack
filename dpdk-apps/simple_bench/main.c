
#include <stdint.h>
#include <inttypes.h>
#include <unistd.h>
#include <getopt.h>
#include <string.h>
#include <execinfo.h>
#include <unistd.h>
#include <signal.h>
#include <stdbool.h>

#include <rte_common.h>
#include <rte_malloc.h>
#include <rte_memory.h>
#include <rte_memcpy.h>
#include <rte_memzone.h>
#include <rte_eal.h>
#include <rte_per_lcore.h>
#include <rte_launch.h>
#include <rte_atomic.h>
#include <rte_cycles.h>
#include <rte_prefetch.h>
#include <rte_lcore.h>
#include <rte_branch_prediction.h>
#include <rte_interrupts.h>
#include <rte_pci.h>
#include <rte_debug.h>
#include <rte_ethdev.h>
#include <rte_ring.h>
#include <rte_mempool.h>
#include <rte_mbuf.h>
#include <rte_log.h>


#include "init.h"
#include "bench_sender.h"

static bool running;
struct app_config * appconfig;

static
void handler(int sig) {
    void *array[10];
    size_t size;

    // get void*'s for all entries on the stack
    size = backtrace(array, 10);

    // print out all the frames to stderr
    fprintf(stderr, "Error: signal %d:\n", sig);
    backtrace_symbols_fd(array, size, STDERR_FILENO);
    
    die();
}

// static uint64_t
// extract_timestamp(struct rte_mbuf *m) {
//     struct ipv4_hdr *ip_hdr;
//     uint64_t* msg_start;

//     if (m->data_len < MIN_PKT_SIZE) return 0;

//     ip_hdr = rte_pktmbuf_mtod_offset(m, struct ipv4_hdr *, sizeof(struct ether_hdr));

//     if (ip_hdr->next_proto_id != IPPROTO_UDP) return 0;

//     msg_start =  (uint64_t*) rte_pktmbuf_mtod_offset(m, char*, sizeof(struct ether_hdr) 
//                     + sizeof(struct ipv4_hdr) + sizeof(struct udp_hdr));

//     uint64_t timestamp = *msg_start;
//     return timestamp;
// }

// /*
//  * This lcore receives udp packets containing a timespamp and saves the secs
//  * between sent and receive.
//  */
// static void
// lcore_receive_bench(void) {
//     const uint16_t port = 1;
//     /*
//      * Check that the port is on the same NUMA node as the polling thread
//      * for best performance.
//      */
//     if (rte_eth_dev_socket_id(port) > 0 &&
//             rte_eth_dev_socket_id(port) != (int)rte_socket_id())
//         printf("WARNING, port %u is on remote NUMA node to "
//                 "polling thread.\n\tPerformance will "
//                 "not be optimal.\n", port);

//     printf("\nCore %u receiving packets. [Ctrl+C to quit]\n", rte_lcore_id());


//     struct rte_mbuf *pkts_burst[BURST_SIZE];
//     uint64_t last_stat_update = rte_get_timer_cycles();
//     unsigned nb_rx;

//     while(running) {
//         uint64_t time = rte_get_timer_cycles();

//         nb_rx = rte_eth_rx_burst((uint8_t) port, 0,
//                         pkts_burst, BURST_SIZE);

//         port_statistics[port].rx += nb_rx;

//         uint64_t sum_duration = 0;
//         unsigned skiped_pkts = 0;
//         unsigned index;
        
//         for (index = 0; index < nb_rx; ++index) {
//             uint64_t duration = extract_timestamp(pkts_burst[index]);

//             if (duration != 0) {
//                 sum_duration += duration;
//             } else {
//                 ++skiped_pkts;
//             }
//         }

//         if (time - last_stat_update > STAT_UPDATE_INTERVAL) {
//             print_stats();
//             last_stat_update = time;
//         }
//     }
// }

static void
signal_handler(int signum)
{
    if (signum == SIGINT || signum == SIGTERM) {
        printf("\n\nSignal %d received, preparing to exit...\n",
                signum);
        running = false;
    }
}

static int
main_loop(void * arg) {
    struct core_config * c = (struct core_config *) arg;

    while (running) {

        /* Poll bench packet sender. */
        for (unsigned i = 0; i < c->bench_send_count; i++) {
            bench_send_poll(c->bench_senders[i]);
        }
        c->nb_polls++;
    }
    return 0;
}

/*
 * Free allocated memory and close ports.
 */
static void
tear_down(struct app_config * app_config) {
    const unsigned nb_ports = app_config->nb_ports;
    const unsigned enabled_port_mask = app_config->enabled_ports;

    for (unsigned portid = 0; portid < nb_ports; portid++) {
        if ((enabled_port_mask & (1 << portid)) == 0)
            continue;
        printf("Closing port %d...", portid);
        rte_eth_dev_stop(portid);
        rte_eth_dev_close(portid);
        printf(" Done\n");
    }

    free(app_config);
}

static void
print_stats(void) {
    /* Poll bench packet sender. */
    for (unsigned i = 0; i < appconfig->nb_cores; i++) {
        printf("Core %"PRIu32" polled %"PRIu64" times.\n", 
               appconfig->core_configs[i].core, appconfig->core_configs[i].nb_polls);
    }
}

/* display usage */
static void
usage(const char *prgname)
{
    printf("Usage: %s [EAL options] -- <config file>\n", prgname);
}


/*
 * The main function, which does initialization and calls the per-lcore
 * functions.
 */
int
main(int argc, char *argv[])
{
    running = true;
    signal(SIGSEGV, handler);
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    rte_openlog_stream(NULL);

    /* Initialize the Environment Abstraction Layer (EAL). */
    int args_used = rte_eal_init(argc, argv);
    if (args_used < 0)
        rte_exit(EXIT_FAILURE, "Error with EAL initialization\n");

    argc -= args_used;
    argv += args_used;

    if (argc != 2) {
        // we need a config file!
        usage(argv[0]);
        return 0;
    }

    /* Get the desired configuration */
    appconfig = malloc(sizeof(struct app_config));
    if (read_config(argv[1], appconfig) != 0)
        rte_exit(EXIT_FAILURE, "Configuration failed.\n");

    /* run main loop on worker cores */
    for (unsigned i = 1; i < appconfig->nb_cores; i++) {
        rte_eal_remote_launch(main_loop, &appconfig->core_configs[i], appconfig->core_configs[i].core);
    }

    /* run main loop on master core */
    main_loop(&appconfig->core_configs[0]);

    printf("Waiting for Core");

    /* wait for all worker to finish */
    int exit_code = 0;
    int core_id;
    RTE_LCORE_FOREACH_SLAVE(core_id) {
        if (rte_eal_wait_lcore(core_id) < 0) {
            exit_code = -1;
            break;
        } else {
            printf(" %"PRIu32, core_id);
        }
    }
    printf(" done.\n");

    print_stats();

    /* free all used memory space and exit */
    tear_down(appconfig);
    printf("Bye...\n");

    return exit_code;
}
