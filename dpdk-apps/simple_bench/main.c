
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
#include <rte_log.h>
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
#include <rte_per_lcore.h>
#include <rte_branch_prediction.h>
#include <rte_interrupts.h>
#include <rte_pci.h>
#include <rte_random.h>
#include <rte_debug.h>
#include <rte_ether.h>
#include <rte_ethdev.h>
#include <rte_ring.h>
#include <rte_mempool.h>
#include <rte_mbuf.h>
#include <rte_byteorder.h>
#include <rte_ip.h>
#include <rte_udp.h>

/* requirements for app */
#define NUMBER_CORES 2
#define NUMBER_PORTS 2

/* constants */
#define OK       0
#define NO_INPUT 1
#define TOO_LONG 2

/* configuration */
#define SEND_INTERVAL 50
#define STAT_UPDATE_INTERVAL 1000

#define RX_RING_SIZE 128
#define TX_RING_SIZE 512

#define NUM_MBUFS 8191
#define MBUF_CACHE_SIZE 250
#define BURST_SIZE 32

static const struct rte_eth_conf port_conf_default = {
    .rxmode = { .max_rx_pkt_len = ETHER_MAX_LEN }
};

/* Per-port statistics struct */
struct port_statistics {
    uint64_t tx;
    uint64_t rx;
    uint64_t dropped;
} __rte_cache_aligned;
struct port_statistics port_statistics[RTE_MAX_ETHPORTS];
static uint64_t pkts_received = 0;
static uint64_t sum_rtt = 0;

/* configuration for packet */
static struct ether_addr src_mac_addr;
static struct ether_addr dst_mac_addr;
static uint32_t src_ip_addr = 0;
static uint32_t dst_ip_addr = 0;
static uint16_t dst_udp_port = 666;

/* mbuf pool */
static struct rte_mempool *mbuf_pool;
static struct rte_mbuf *m_array[1];

/* mask of enabled ports */
static uint32_t enabled_port_mask = 0;

static uint32_t MIN_PKT_SIZE = sizeof(struct ether_hdr) + sizeof(struct ipv4_hdr) 
                + sizeof(struct udp_hdr) + sizeof(uint64_t);
static volatile bool force_quit;

static
void handler(int sig) {
    void *array[10];
    size_t size;

    // get void*'s for all entries on the stack
    size = backtrace(array, 10);

    // print out all the frames to stderr
    fprintf(stderr, "Error: signal %d:\n", sig);
    backtrace_symbols_fd(array, size, STDERR_FILENO);
    exit(1);
}

static void
print_int32_ip(uint32_t int32) {
    uint8_t * ints = (uint8_t*) &int32;
    int i;
    for (i = 0; i < 4; i++)
    {
        if (i > 0) printf(".");
        printf("%d", ints[3-i]);
    }
}

/* Print out statistics on packets dropped */
static void
print_stats(void)
{
    uint64_t total_packets_dropped, total_packets_tx, total_packets_rx;
    unsigned portid;

    total_packets_dropped = 0;
    total_packets_tx = 0;
    total_packets_rx = 0;

    const char clr[] = { 27, '[', '2', 'J', '\0' };
    const char topLeft[] = { 27, '[', '1', ';', '1', 'H','\0' };

        /* Clear screen and move to top left */
    printf("%s%s", clr, topLeft);

    printf("\nPort statistics ====================================");

    for (portid = 0; portid < RTE_MAX_ETHPORTS; portid++) {
        /* skip disabled ports */
        if ((enabled_port_mask & (1 << portid)) == 0)
            continue;
        printf("\nStatistics for port %u ------------------------------"
               "\nPackets sent: %24"PRIu64
               "\nPackets received: %20"PRIu64
               "\nPackets dropped: %21"PRIu64,
               portid,
               port_statistics[portid].tx,
               port_statistics[portid].rx,
               port_statistics[portid].dropped);

        total_packets_dropped += port_statistics[portid].dropped;
        total_packets_tx += port_statistics[portid].tx;
        total_packets_rx += port_statistics[portid].rx;
    }
    printf("\nAggregate statistics ==============================="
           "\nTotal packets sent: %18"PRIu64
           "\nTotal packets received: %14"PRIu64
           "\nTotal packets dropped: %15"PRIu64
           "\nAvg   RTT: %27"PRIu64,
           total_packets_tx,
           total_packets_rx,
           total_packets_dropped,
           (sum_rtt / pkts_received)
           );
    printf("\n====================================================\n");
}


/*
 * Initializes a given port using global settings and with the RX buffers
 * coming from the mbuf_pool passed as a parameter.
 */
static inline int
port_init(uint8_t port)
{
    struct rte_eth_conf port_conf = port_conf_default;
    const uint16_t rx_rings = 1, tx_rings = 1;
    int retval;
    uint16_t q;

    if (port >= rte_eth_dev_count())
        return -1;

    retval = rte_eth_dev_configure(port, rx_rings, tx_rings, &port_conf);
    if (retval != 0)
        return retval;

    for (q = 0; q < rx_rings; q++) {
        retval = rte_eth_rx_queue_setup(port, q, RX_RING_SIZE,
                                        rte_eth_dev_socket_id(port), NULL, mbuf_pool);
        if (retval < 0)
                return retval;
    }

    for (q = 0; q < tx_rings; q++) {
        retval = rte_eth_tx_queue_setup(port, q, TX_RING_SIZE,
                                            rte_eth_dev_socket_id(port), NULL);
        if (retval < 0)
            return retval;
    }

    retval  = rte_eth_dev_start(port);
    if (retval < 0)
        return retval;


    rte_eth_macaddr_get(port, &src_mac_addr);
    printf("Port %u MAC: %02" PRIx8 " %02" PRIx8 " %02" PRIx8
           " %02" PRIx8 " %02" PRIx8 " %02" PRIx8 "\n",
           (unsigned)port,
           src_mac_addr.addr_bytes[0], src_mac_addr.addr_bytes[1],
           src_mac_addr.addr_bytes[2], src_mac_addr.addr_bytes[3],
           src_mac_addr.addr_bytes[4], src_mac_addr.addr_bytes[5]);

    rte_eth_promiscuous_enable(port);

    return 0;
}

static void
send_packet(uint8_t port, char* msg, uint32_t msg_size) {
    uint32_t pkt_size;
    struct ether_hdr *eth_hdr;
    struct ipv4_hdr *ip_hdr;
    struct udp_hdr *udp_hdr;
    char* msg_start;

    pkt_size = sizeof(struct ether_hdr) + sizeof(struct ipv4_hdr) 
                + sizeof(struct udp_hdr) + msg_size * sizeof(char);
    
    m_array[0] = rte_pktmbuf_alloc(mbuf_pool);
    struct rte_mbuf *m = m_array[0];

    m->data_len = pkt_size;
    m->pkt_len = pkt_size;

    eth_hdr = rte_pktmbuf_mtod(m, struct ether_hdr *);
    memcpy((void*) &eth_hdr->d_addr, dst_mac_addr.addr_bytes, ETHER_ADDR_LEN);
    memcpy((void*) &eth_hdr->s_addr, &src_mac_addr, ETHER_ADDR_LEN);
    eth_hdr->ether_type = rte_cpu_to_be_16(ETHER_TYPE_IPv4);

    ip_hdr = rte_pktmbuf_mtod_offset(m, struct ipv4_hdr *, sizeof(struct ether_hdr));
    ip_hdr->version_ihl = 0x45;
    ip_hdr->time_to_live = 64;
    ip_hdr->src_addr = rte_cpu_to_be_32(src_ip_addr);
    ip_hdr->dst_addr = rte_cpu_to_be_32(dst_ip_addr);
    ip_hdr->next_proto_id = IPPROTO_UDP;
    ip_hdr->total_length = pkt_size - sizeof(struct ether_hdr);

    ip_hdr->hdr_checksum  = rte_ipv4_cksum(ip_hdr);

    udp_hdr = rte_pktmbuf_mtod_offset(m, struct udp_hdr *, 
        sizeof(struct ether_hdr) + sizeof(struct ipv4_hdr));
    udp_hdr->src_port = 0;
    udp_hdr->dst_port = rte_cpu_to_be_16(dst_udp_port);
    udp_hdr->dgram_len = rte_cpu_to_be_16(msg_size + sizeof(struct udp_hdr));
    msg_start = rte_pktmbuf_mtod_offset(m, char*, sizeof(struct ether_hdr) 
                    + sizeof(struct ipv4_hdr) + sizeof(struct udp_hdr));
    memcpy(msg_start, msg, msg_size);

    udp_hdr->dgram_cksum = rte_cpu_to_be_16(rte_ipv4_udptcp_cksum(ip_hdr, (const void *) udp_hdr));

    int sent = rte_eth_tx_burst(port, 0, m_array, 1);

    if (sent)
        port_statistics[port].tx += sent;
}

/*
 * This lcore sends udp packets containing a timestamp.
 */
static void
lcore_send_bench(void)
{
    const uint16_t port = 0;
    /*
     * Check that the port is on the same NUMA node as the polling thread
     * for best performance.
     */
    if (rte_eth_dev_socket_id(port) > 0 &&
            rte_eth_dev_socket_id(port) !=
                    (int)rte_socket_id())
        printf("WARNING, port %u is on remote NUMA node to "
                "polling thread.\n\tPerformance will "
                "not be optimal.\n", port);

    printf("\nCore %u sending packets. [Ctrl+C to quit]\n", rte_lcore_id());

    while(!force_quit) {
        uint64_t time = rte_get_timer_cycles();
        send_packet(port, (char*) &time, sizeof(time));

        usleep(SEND_INTERVAL);
    }
}

static uint64_t
extract_timestamp(struct rte_mbuf *m) {
    struct ipv4_hdr *ip_hdr;
    uint64_t* msg_start;

    if (m->data_len < MIN_PKT_SIZE) return 0;

    ip_hdr = rte_pktmbuf_mtod_offset(m, struct ipv4_hdr *, sizeof(struct ether_hdr));

    if (ip_hdr->next_proto_id != IPPROTO_UDP) return 0;

    msg_start =  (uint64_t*) rte_pktmbuf_mtod_offset(m, char*, sizeof(struct ether_hdr) 
                    + sizeof(struct ipv4_hdr) + sizeof(struct udp_hdr));

    uint64_t timestamp = *msg_start;
    return timestamp;
}

/*
 * This lcore receives udp packets containing a timespamp and saves the secs
 * between sent and receive.
 */
static void
lcore_receive_bench(void) {
    const uint16_t port = 1;
    /*
     * Check that the port is on the same NUMA node as the polling thread
     * for best performance.
     */
    if (rte_eth_dev_socket_id(port) > 0 &&
            rte_eth_dev_socket_id(port) != (int)rte_socket_id())
        printf("WARNING, port %u is on remote NUMA node to "
                "polling thread.\n\tPerformance will "
                "not be optimal.\n", port);

    printf("\nCore %u receiving packets. [Ctrl+C to quit]\n", rte_lcore_id());


    struct rte_mbuf *pkts_burst[BURST_SIZE];
    uint64_t last_stat_update = rte_get_timer_cycles();
    unsigned nb_rx;

    while(!force_quit) {
        uint64_t time = rte_get_timer_cycles();

        nb_rx = rte_eth_rx_burst((uint8_t) port, 0,
                        pkts_burst, BURST_SIZE);

        port_statistics[port].rx += nb_rx;

        uint64_t sum_duration = 0;
        unsigned skiped_pkts = 0;
        unsigned index;
        
        for (index = 0; index < nb_rx; ++index) {
            uint64_t duration = extract_timestamp(pkts_burst[index]);

            if (duration != 0) {
                sum_duration += duration;
            } else {
                ++skiped_pkts;
            }
        }

        if (time - last_stat_update > STAT_UPDATE_INTERVAL) {
            print_stats();
            last_stat_update = time;
        }
    }
}

static int
parse_portmask(const char *portmask)
{
    char *end = NULL;
    unsigned long pm;

    /* parse hexadecimal string */
    pm = strtoul(portmask, &end, 16);
    if ((portmask[0] == '\0') || (end == NULL) || (*end != '\0'))
        return -1;

    if (pm == 0)
        return -1;

    return pm;
}

/* display usage */
static void
usage(const char *prgname)
{
    printf("%s [EAL options] --\n"
            "  -p PORTMASK: hexadecimal bitmask of ports to configure\n"
            "  -m MAC: mac address where packets should be send to\n"
            "  -s IP: source IP\n"
            "  -d IP: destination IP\n"
            "  -u PORT: destination UDP port\n",
            prgname);
}

static uint16_t
parse_int16(const char *int_str) {
    char *end = NULL;
    int index = 0;
    printf("%p\n", int_str);
    while (int_str[index]) {
        printf("%c", int_str[index]);
        ++index;
    }

    return strtoul(int_str, &end, 10);
}

static void
parse_ipv4(const char *ip_str, uint8_t *ip) {
    char *end = NULL;
    const char *start = ip_str;

    int index;
    /* parse decimal string */
    for (index = 0; index < 4; index++) {
        ip[3-index] = strtoul(start, &end, 10);

        start = end + 1;
    }
}

static void
parse_mac(const char *mac_str, struct ether_addr *mac) {
    int index;
    /* parse hexadecimal string */
    for (index = 0; index < ETHER_ADDR_LEN; index++) {
        mac->addr_bytes[index] = strtoul(mac_str, NULL, 16);
        mac_str += 3;
    }
}

/* Parse the argument given in the command line of the application */
static int
parse_args(int argc, char **argv)
{
    int opt, ret;
    char **argvopt;
    int option_index;
    char *prgname = argv[0];
    static struct option lgopts[] = {
        {NULL, 0, 0, 0}
    };

    argvopt = argv;

    while ((opt = getopt_long(argc, argvopt, "p:m:s:d:u",
                  lgopts, &option_index)) != EOF) {

        switch (opt) {
        /* portmask */
        case 'p':
            enabled_port_mask = parse_portmask(optarg);
            if (enabled_port_mask == 0) {
                printf("invalid portmask\n");
                usage(prgname);
                return -1;
            }
            break;
        /* destination mac address */
        case 'm':
            parse_mac(optarg, &dst_mac_addr);

            printf("dst MAC address: %02X:%02X:%02X:%02X:%02X:%02X\n\n",
                    dst_mac_addr.addr_bytes[0],
                    dst_mac_addr.addr_bytes[1],
                    dst_mac_addr.addr_bytes[2],
                    dst_mac_addr.addr_bytes[3],
                    dst_mac_addr.addr_bytes[4],
                    dst_mac_addr.addr_bytes[5]);
            break;
        /* source ip address */
        case 's':
            parse_ipv4(optarg, (uint8_t*) &src_ip_addr);

            printf("src IP address: ");
            print_int32_ip(src_ip_addr);
            printf("\n");
            break;
        /* destination ip address */
        case 'd':
            parse_ipv4(optarg, (uint8_t*) &dst_ip_addr);

            printf("dst IP address: ");
            print_int32_ip(dst_ip_addr);
            printf("\n");
            break;
        /* destination upd port */
        case 'u':
            printf("start pars udp\n");
            dst_udp_port = parse_int16(optarg);

            printf("UDP port: %d\n", dst_udp_port);
            break;

        /* long options */
        case 0:
            usage(prgname);
            return -1;

        default:
            usage(prgname);
            return -1;
        }
    }

    if (optind >= 0)
        argv[optind-1] = prgname;

    ret = optind-1;
    optind = 0; /* reset getopt lib */
    return ret;
}

static void
signal_handler(int signum)
{
    if (signum == SIGINT || signum == SIGTERM) {
        printf("\n\nSignal %d received, preparing to exit...\n",
                signum);
        force_quit = true;
    }
}

/*
 * The main function, which does initialization and calls the per-lcore
 * functions.
 */
int
main(int argc, char *argv[])
{
    force_quit = false;
    signal(SIGSEGV, handler);
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    unsigned nb_ports;
    uint8_t portid;

    /* Initialize the Environment Abstraction Layer (EAL). */
    int ret = rte_eal_init(argc, argv);
    if (ret < 0)
        rte_exit(EXIT_FAILURE, "Error with EAL initialization\n");

    argc -= ret;
    argv += ret;

    ret = parse_args(argc, argv);
    if (ret < 0)
        rte_exit(EXIT_FAILURE, "Invalid SIMPLE_BENCH arguments\n");


    /* Check that there is an even number of ports to send/receive on. */
    nb_ports = rte_eth_dev_count();
    if (nb_ports != NUMBER_CORES)
        rte_exit(EXIT_FAILURE, "Error: number of ports must be %"PRIu32" got: %"PRIu8 "\n",
            NUMBER_PORTS, nb_ports);

    /* Creates a new mempool in memory to hold the mbufs. */
    mbuf_pool = rte_pktmbuf_pool_create("MBUF_POOL", NUM_MBUFS * nb_ports,
        MBUF_CACHE_SIZE, 0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());


    if (mbuf_pool == NULL)
        rte_exit(EXIT_FAILURE, "Cannot create mbuf pool\n");

    /* Initialize all ports. */
    portid = 0;
    if (port_init(portid) != 0)
        rte_exit(EXIT_FAILURE, "Cannot init port %"PRIu8 "\n",
                portid);

    if (rte_lcore_count() != NUMBER_CORES)
        rte_exit(EXIT_FAILURE, "Error: Number of cores must be %"PRIu32".\n", NUMBER_CORES);

    unsigned last_lcore = rte_lcore_id();

        /* start lcore_receive_bench. */
    {
        unsigned receive_lcore_num = rte_get_next_lcore(last_lcore, 0, 1);
        last_lcore = receive_lcore_num;

        if (receive_lcore_num != RTE_MAX_LCORE) {
            rte_eal_remote_launch((lcore_function_t *)lcore_receive_bench, 
                                    NULL, receive_lcore_num);
        } else {
            rte_exit(EXIT_FAILURE, "Error2: could not get lcore ID!\n");
        }        
    }

        /* start lcore_send_bench. */
    {
        unsigned send_lcore_num = rte_get_next_lcore(last_lcore, 0, 1);
        last_lcore = send_lcore_num;
    
        if (send_lcore_num != RTE_MAX_LCORE) {
            rte_eal_remote_launch((lcore_function_t *)lcore_send_bench, 
                NULL, send_lcore_num);
        } else {
            rte_exit(EXIT_FAILURE, "Error1: could not get lcore ID!\n");
        }
    }

    unsigned lcore_id;
    RTE_LCORE_FOREACH_SLAVE(lcore_id) {
        if (rte_eal_wait_lcore(lcore_id) < 0) {
            ret = -1;
            break;
        }
    }

    for (portid = 0; portid < nb_ports; portid++) {
        if ((enabled_port_mask & (1 << portid)) == 0)
            continue;
        printf("Closing port %d...", portid);
        rte_eth_dev_stop(portid);
        rte_eth_dev_close(portid);
        printf(" Done\n");
    }
    printf("Bye...\n");

    return 0;
}