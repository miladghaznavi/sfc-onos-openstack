#include <stdint.h>
#include <inttypes.h>
#include <unistd.h>
#include <getopt.h>
#include <string.h>
#include <execinfo.h>
#include <unistd.h>
#include <signal.h>
#include <stdbool.h>
#include <unistd.h>

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
#include <rte_errno.h>

#include "init.h"

#define RTE_LOGTYPE_MAIN RTE_LOGTYPE_USER1
#define RTE_LOGTYPE_STAT RTE_LOGTYPE_USER2

static bool running;
struct app_config * appconfig;

static uint64_t last_stat = 0;
static uint64_t last_used_count = 0;

static
void handler(int sig) {
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
}

static void
signal_handler(int signum) {
    if (signum == SIGINT || signum == SIGTERM) {
        RTE_LOG(ERR, MAIN, "\n\nSignal %d received, preparing to exit...\n",
                signum);
        running = false;
    }
}

static int
main_loop(void * arg) {
    struct core_config * c = (struct core_config *) arg;

    while (running) {
        for (unsigned i = 0; i < c->nb_receiver; i++) {
            poll_receiver(c->receiver[i]);
        }

        /* Poll bench packet sender. */
        for (unsigned i = 0; i < c->nb_bench_sender; i++) {
            poll_bench_sender(c->bench_senders[i]);
        }

        // /* Poll bench packet receiver. */
        // for (unsigned i = 0; i < c->nb_bench_receiver; i++) {
        //     poll_bench_receiver(c->bench_receivers[i]);
        // }

        // /* Poll bench packet receiver. */
        // for (unsigned i = 0; i < c->nb_bench_forwarder; i++) {
        //     poll_bench_forwarder(c->bench_forwarders[i]);
        // }

        // for (unsigned i = 0; i < c->nb_counter; i++) {
        //     poll_counter(c->counter[i]);
        // }

        c->nb_polls++;
    }
    return 0;
}

static void
print_stats(void) {
    for (unsigned i = 0; i < appconfig->nb_receiver; i++) {
        log_receiver(appconfig->receiver[i]);
    }

    for (unsigned i = 0; i < appconfig->nb_forwarder; i++) {
        log_forwarder(appconfig->forwarder[i]);
    }

    for (unsigned i = 0; i < appconfig->nb_mirrow; i++) {
        log_mirrow(appconfig->mirrow[i]);
    }

    for (unsigned i = 0; i < appconfig->nb_counter; i++) {
        log_counter(appconfig->counter[i]);
    }

    /* log bench packet sender. */
    for (unsigned i = 0; i < appconfig->nb_bench_sender; i++) {
        log_bench_sender(appconfig->bench_senders[i]);
    }
    
    /* log bench packet receiver. */
    for (unsigned i = 0; i < appconfig->nb_bench_receiver; i++) {
        log_bench_receiver(appconfig->bench_receivers[i]);
    }
    RTE_LOG(INFO, MAIN, "Clone Pool: %"PRIu32"\n", rte_mempool_count(appconfig->clone_pool));
    RTE_LOG(INFO, MAIN, "Packet Pool: %"PRIu32"\n", rte_mempool_count(appconfig->pkt_pool));

    uint64_t now = rte_get_tsc_cycles();
    uint64_t passed_cycles = now - last_stat;

    for (unsigned i = 0; i < appconfig->nb_cores; i++) {
        struct core_config *core_config = &appconfig->core_configs[i];
        double used_cycle = 0;
        for (unsigned i = 0; i < core_config->nb_receiver; i++) {
            used_cycle += core_config->receiver[i]->time_a;
        }
        RTE_LOG(INFO, MAIN, "CPU %d usage: %f %%\n", core_config->core, 
            (used_cycle - core_config->last_stat_used_cycles) * 100.0f / (double)passed_cycles);
        core_config->last_stat_used_cycles = used_cycle;
    }

    last_stat = rte_get_tsc_cycles();
}

static void*
stats_loop(void *dummy) {

    while (running) {
        nanosleep((const struct timespec[]){{2, 0}}, NULL);

        /* Clear screen and move to top left */
        const char clr[] = { 27, '[', '2', 'J', '\0' };
        const char topLeft[] = { 27, '[', '1', ';', '1', 'H','\0' };
        printf("%s%s", clr, topLeft);

        print_stats();
    }
}

/* display usage */
static void
usage(const char *prgname) {
    printf("Usage: %s [EAL options] -- <config file>\n", prgname);
}

/*
 * Free allocated memory and close ports.
 */
static void
tear_down(struct app_config *app_config) {
    const unsigned nb_ports = app_config->nb_ports;
    const unsigned enabled_port_mask = app_config->enabled_ports;

    for (unsigned portid = 0; portid < nb_ports; portid++) {
        if ((enabled_port_mask & (1 << portid)) == 0)
            continue;
        RTE_LOG(INFO, MAIN, "Closing port %d...", portid);
        rte_eth_dev_stop(portid);
        rte_eth_dev_close(portid);
        printf(" Done\n");
    }

    rte_free(app_config);
}

/*
 * The main function, which does initialization and calls the per-lcore
 * functions.
 */
int
main(int argc, char *argv[]) {
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
    appconfig = rte_malloc(NULL, sizeof(struct app_config), 64);
    if (read_config(argv[1], appconfig) != 0)
        rte_exit(EXIT_FAILURE, "Configuration failed.\n");

    /* run main loop on worker cores */
    for (unsigned i = 1; i < appconfig->nb_cores; i++) {
        RTE_LOG(INFO, MAIN, "Start Core: %"PRIu32".\n", appconfig->core_configs[i].core);
        rte_eal_remote_launch(main_loop, &appconfig->core_configs[i], appconfig->core_configs[i].core);
    }
    
    // RTE_LOG(INFO, MAIN, "Start stat thread.\n");
    pthread_t stat;
    pthread_create(&stat, NULL, stats_loop, NULL);

    /* run main loop on master core */
    RTE_LOG(INFO, MAIN, "Start main loop on master core.\n");

    main_loop(&appconfig->core_configs[0]);

    RTE_LOG(INFO, MAIN, "Stopping...\n");
    RTE_LOG(INFO, MAIN, "Waiting for Core");
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
    RTE_LOG(INFO, MAIN, " done.\n");

    print_stats();

    /* free all used memory space and exit */
    tear_down(appconfig);
    RTE_LOG(INFO, MAIN, "Bye...\n");

    return exit_code;
}
