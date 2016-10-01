#ifndef HELLO_H_
#define HELLO_H_

#include <inttypes.h>
#include <libconfig.h>
#include <stdbool.h>

#include <rte_mbuf.h>
#include <rte_ethdev.h>

struct app_config;

struct hello_t {
    struct transmit_t *tx;

    struct rte_mbuf *hello_proto;
    
    struct rte_mempool *pool;
    struct rte_mempool *clone_pool;
};

void
log_hello(struct counter_t *counter);

void
poll_hello(struct counter_t *counter);

int
get_hello(config_setting_t *c_conf,
            struct app_config *appconfig, 
            struct counter_t *counter);


#endif /* HELLO_H_ */
