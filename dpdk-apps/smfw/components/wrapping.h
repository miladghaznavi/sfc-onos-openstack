#ifndef WRAPPING_H_
#define WRAPPING_H_

#include <assert.h>

#include <rte_mempool.h>
#include <rte_mbuf.h>
#include <rte_ethdev.h>
#include <rte_ip.h>
#include <rte_hash_crc.h>
#include <rte_malloc.h>

#include "../rxtx.h"
#include "../parse.h"

#define RTE_LOGTYPE_WRAPPER RTE_LOGTYPE_USER1

/**
 * Specifies how man bytes of the original packet (starting after Layer2)
 * should be kept when compressing the packet
 *
 * Typically IPv4 + TCP is is 42 Bytes,
 * so 64 should be enough to keep connection information
 */
#define COMPRESSED_DATA_SIZE 64

#define WRAPPER_COMPRESS_NULL   0
#define WRAPPER_COMPRESS_CRC32  1
#define WRAPPER_COMPRESS_SHA256 2
#define WRAPPER_COMPRESS_SHA512 3

/**
 * Active Compression Method
 * Possible values: WRAPPER_COMPRESS_NULL, WRAPPER_COMPRESS_CRC32,
 *                  WRAPPER_COMPRESS_SHA256, WRAPPER_COMPRESS_SHA512
 */
#define WRAPPER_COMPRESS WRAPPER_COMPRESS_NULL

#if WRAPPER_COMPRESS == WRAPPER_COMPRESS_SHA256 || \
	WRAPPER_COMPRESS == WRAPPER_COMPRESS_SHA512
#include <openssl/sha.h>
#endif

#define METADATA_LEN sizeof(struct wrapper_metadata)


/** Metadata structure to add to packets */
struct metadata_t {
	uint64_t decissions;
} __attribute__((__packed__));

struct wrapper_compressed {
  uint32_t hash_crc;

#if WRAPPER_COMPRESS == WRAPPER_COMPRESS_SHA256
  uint8_t hash_sha256[32];
#endif

#if WRAPPER_COMPRESS == WRAPPER_COMPRESS_SHA512
  uint8_t hash_sha512[64];
#endif
} __attribute__((__packed__));

static void
wrapper_compress(struct rte_mempool *pkt_pool, struct rte_mbuf *packet) {
	#if WRAPPER_COMPRESS == WRAPPER_COMPRESS_NULL
	return;
	#endif

	size_t keep_bytes = sizeof(struct ether_hdr) + COMPRESSED_DATA_SIZE;

	struct rte_mbuf * buf_tail = rte_pktmbuf_alloc(pkt_pool);
	if (buf_tail == NULL) {
		RTE_LOG(ERR, WRAPPER, "Could not alloc mBUF.\n");
	}
	buf_tail->data_len = sizeof(struct wrapper_compressed);
	struct wrapper_compressed * compress = rte_pktmbuf_mtod(buf_tail, struct wrapper_compressed *);

	char *data;
	unsigned data_len = packet->pkt_len - 2* sizeof(struct ether_addr);
	bool should_free = false;

	if (rte_pktmbuf_is_contiguous(packet)) {
		data = rte_pktmbuf_mtod_offset(packet, char *, 2* sizeof(struct ether_addr));
		rte_pktmbuf_trim(packet, packet->data_len - keep_bytes);

	} else {
		// data = rte_malloc(NULL, data_len, 64);
		data = malloc(data_len);
		should_free = true;

		{	// get Data
			struct rte_mbuf *seg = packet;
			size_t copy_size = packet->data_len - 2*sizeof(struct ether_addr);
			memcpy(data, rte_pktmbuf_mtod_offset(packet, char *, 2*sizeof(struct ether_addr)), copy_size);

			int i = copy_size;
			while (i < data_len) {
				if (seg->next == NULL) break;
				seg = seg->next;

				memcpy(data + i, rte_pktmbuf_mtod(seg, char *), seg->data_len);
				i += seg->data_len;

			}
		}

		{	// remove data
			struct rte_mbuf *seg = packet;
			size_t nb_segs = 1;
			while (seg->data_len < keep_bytes) {
				keep_bytes -= seg->data_len;
				if (seg->next == NULL) break;
				seg = seg->next;
				nb_segs++;
			}
			if (seg->data_len > keep_bytes) {
				rte_pktmbuf_free(seg->next);
				seg->next = NULL;
				rte_pktmbuf_trim(seg, seg->data_len - keep_bytes);
				packet->nb_segs = nb_segs;
				packet->pkt_len = sizeof(struct ether_hdr) + COMPRESSED_DATA_SIZE;
			} // else -> nmdf-chaos!!

		}
	}

	// Identifier for indextable
	compress->hash_crc = rte_hash_crc(data, data_len, 0);

	#if WRAPPER_COMPRESS == WRAPPER_COMPRESS_SHA256
	SHA256(data, data_len, compress->hash_sha256);
	#endif
	
	#if WRAPPER_COMPRESS == WRAPPER_COMPRESS_SHA512
	SHA512(data, data_len, compress->hash_sha512);
	#endif
	// if (should_free) rte_free(data);
	if (should_free) free(data);

	rte_pktmbuf_chain(packet, buf_tail);
	rte_mbuf_sanity_check(packet, 1);
}

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
