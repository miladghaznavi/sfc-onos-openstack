#ifndef WRAPPING_H_
#define WRAPPING_H_

#include <assert.h>

#include <rte_mempool.h>
#include <rte_mbuf.h>
#include <rte_ethdev.h>
#include <rte_ip.h>

#include "../rxtx.h"

#define RTE_LOGTYPE_WRAPPER RTE_LOGTYPE_USER1

/** Metadata structure to add to packets */
struct metadata_t {
	uint64_t decissions;
} __attribute__((__packed__));


static int
wrapper_add_data(struct rte_mbuf *packet, struct metadata_t *metadata) {

	// try to append some bytes
	char *added_data = rte_pktmbuf_append(packet, sizeof(struct metadata_t));

	if (added_data == NULL) {
		RTE_LOG(ERR, WRAPPER, "Not enough tailroom for meta!!\n");
		return 1;
	}
	memcpy(added_data, metadata, sizeof(struct metadata_t));
	return 0;
}

static void
wrapper_remove_data(struct rte_mbuf *packet) {
	rte_pktmbuf_trim(packet, sizeof(struct metadata_t));
}

static struct metadata_t*
wrapper_get_data(struct rte_mbuf *m_meta) {
	return rte_pktmbuf_mtod_offset(m_meta, struct metadata_t*,
			m_meta->pkt_len - sizeof(struct metadata_t));
}

#endif /* WRAPPING_H_ */
