
#include <stdint.h>
#include <inttypes.h>
#include <unistd.h>
#include <getopt.h>
#include <string.h>
#include <execinfo.h>
#include <unistd.h>
#include <signal.h>

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

#define OK       0
#define NO_INPUT 1
#define TOO_LONG 2

#define RX_RING_SIZE 128
#define TX_RING_SIZE 512

#define NUM_MBUFS 8191
#define MBUF_CACHE_SIZE 250
#define BURST_SIZE 32
#define MAX_MSG_SIZE 512

static const struct rte_eth_conf port_conf_default = {
    .rxmode = { .max_rx_pkt_len = ETHER_MAX_LEN }
};

/* configuration for packet */
static struct ether_addr src_mac_addr;
static struct ether_addr dst_mac_addr;
static uint32_t src_ip_addr = 0;
static uint32_t dst_ip_addr = 0;
static uint16_t dst_udp_port = 666;

/* mbuf pool */
static struct rte_mempool *mbuf_pool;
static struct rte_mbuf *m_array[1];

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

static int 
getLine(const char *prmpt, char *buff, size_t sz) {
    int ch, extra;

    // Get line with buffer overrun protection.
    if (prmpt != NULL) {
        printf("%s", prmpt);
        fflush(stdout);
    }

    if (fgets(buff, sz, stdin) == NULL)
        return NO_INPUT;

    // If it was too long, there'll be no newline. In that case, we flush
    // to end of line so that excess doesn't affect the next call.
    if (buff[strlen(buff)-1] != '\n') {
        extra = 0;
        while (((ch = getchar()) != '\n') && (ch != EOF))
            extra = 1;
        return (extra == 1) ? TOO_LONG : OK;
    }

    // Otherwise remove newline and give string back to caller.
    buff[strlen(buff)-1] = '\0';
    return OK;
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
    ip_hdr->total_length = rte_cpu_to_be_16(pkt_size - sizeof(struct ether_hdr));

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

    printf("UPD size: %"PRIu16"\n", rte_be_to_cpu_16(udp_hdr->dgram_len));
    rte_eth_tx_burst(port, 0, m_array, 1);
}

/*
 * The lcore main. This is the main thread that does the work, reading from
 * an input port and writing to an output port.
 */
static __attribute__((noreturn)) void
lcore_main(void)
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

    char msg[MAX_MSG_SIZE];
    uint32_t state;

    while(1) {
        
        state = getLine("Enter message> ", msg, sizeof(msg));

        if (state == NO_INPUT) {
            // Extra NL since my system doesn't output that on EOF.
            printf("\nNo input\n");

        } else if (state == TOO_LONG) {
            printf("Input too long [max %"PRIu32 "]\n", MAX_MSG_SIZE);

        } else {

            printf("sending: \"%s\" \n", msg);
            send_packet(port, msg, strlen(msg));
        } 
    }

    free(msg);
}

/* display usage */
static void
l2fwd_usage(const char *prgname)
{
    printf("%s [EAL options] --\n"
            "  -m MAC: mac address where packets should be send to\n"
            "  -s IP: source IP\n"
            "  -d IP: destination IP\n"
            "  -u PORT: destination UDP port\n",
            prgname);
}

static uint16_t
l2fwd_parse_int16(const char *int_str) {
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
l2fwd_parse_ipv4(const char *ip_str, uint8_t *ip) {
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
l2fwd_parse_mac(const char *mac_str, struct ether_addr *mac) {
    int index;
    /* parse hexadecimal string */
    for (index = 0; index < ETHER_ADDR_LEN; index++) {
        mac->addr_bytes[index] = strtoul(mac_str, NULL, 16);
        mac_str += 3;
    }
}

/* Parse the argument given in the command line of the application */
static int
l2fwd_parse_args(int argc, char **argv)
{
    int opt, ret;
    char **argvopt;
    int option_index;
    char *prgname = argv[0];
    static struct option lgopts[] = {
        {NULL, 0, 0, 0}
    };

    argvopt = argv;

    while ((opt = getopt_long(argc, argvopt, "m:s:d:u",
                  lgopts, &option_index)) != EOF) {

        switch (opt) {
        /* destination mac address */
        case 'm':
            l2fwd_parse_mac(optarg, &dst_mac_addr);

            printf("dst MAC address: %02X:%02X:%02X:%02X:%02X:%02X\n\n",
                    dst_mac_addr.addr_bytes[0],
                    dst_mac_addr.addr_bytes[1],
                    dst_mac_addr.addr_bytes[2],
                    dst_mac_addr.addr_bytes[3],
                    dst_mac_addr.addr_bytes[4],
                    dst_mac_addr.addr_bytes[5]);
            break;
        case 's':
            l2fwd_parse_ipv4(optarg, (uint8_t*) &src_ip_addr);

            printf("src IP address: ");
            print_int32_ip(src_ip_addr);
            printf("\n");
            break;
        case 'd':
            l2fwd_parse_ipv4(optarg, (uint8_t*) &dst_ip_addr);

            printf("dst IP address: ");
            print_int32_ip(dst_ip_addr);
            printf("\n");
            break;
        case 'u':
            printf("start pars udp\n");
            dst_udp_port = l2fwd_parse_int16(optarg);

            printf("UDP port: %d\n", dst_udp_port);
            break;

        /* long options */
        case 0:
            l2fwd_usage(prgname);
            return -1;

        default:
            l2fwd_usage(prgname);
            return -1;
        }
    }

    if (optind >= 0)
        argv[optind-1] = prgname;

    ret = optind-1;
    optind = 0; /* reset getopt lib */
    return ret;
}

/*
 * The main function, which does initialization and calls the per-lcore
 * functions.
 */
int
main(int argc, char *argv[])
{
    signal(SIGSEGV, handler);

    unsigned nb_ports;
    uint8_t portid;

    /* Initialize the Environment Abstraction Layer (EAL). */
    int ret = rte_eal_init(argc, argv);
    if (ret < 0)
        rte_exit(EXIT_FAILURE, "Error with EAL initialization\n");

    argc -= ret;
    argv += ret;

    ret = l2fwd_parse_args(argc, argv);
    if (ret < 0)
        rte_exit(EXIT_FAILURE, "Invalid L2FWD arguments\n");


    /* Check that there is an even number of ports to send/receive on. */
    nb_ports = rte_eth_dev_count();
    if (nb_ports != 1)
        rte_exit(EXIT_FAILURE, "Error: number of ports must be 1 got: %"PRIu8 "\n",
            nb_ports);

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

    if (rte_lcore_count() > 1)
        printf("\nWARNING: Too many lcores enabled. Only 1 used.\n");

    /* Call lcore_main on the master core only. */
    lcore_main();

    return 0;
}