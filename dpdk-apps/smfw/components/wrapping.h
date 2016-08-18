#ifndef WRAPPING_H_
#define WRAPPING_H_

#include <assert.h>

#include <rte_mempool.h>
#include <rte_mbuf.h>
#include <rte_ethdev.h>
#include <rte_hash_crc.h>
#include <rte_ip.h>

#include "../rxtx.h"

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

/**
 * Specifies how man bytes of the original packet (starting after Layer2)
 * should be kept when compressing the packet
 *
 * Typically IPv4 + TCP is is 42 Bytes,
 * so 64 should be enough to keep connection information
 */
#define WRAPPER_COMPRESS_TRUNCATED_BYTES 64

/** Metadata structure to add to packets */
struct wrapper_metadata {
	uint32_t decissions;
} __attribute__((__packed__));

/** Compression info to add to packets */
struct wrapper_compressed {
	uint32_t hash_crc;

#if WRAPPER_COMPRESS == WRAPPER_COMPRESS_SHA256
	uint8_t hash_sha256[32];
#endif

#if WRAPPER_COMPRESS == WRAPPER_COMPRESS_SHA512
	uint8_t hash_sha512[64];
#endif
} __attribute__((__packed__));

#define METADATA_LEN sizeof(struct wrapper_metadata)
#define SLICE_OFFSET sizeof(struct ether_hdr) + sizeof(struct ipv4_hdr)

/**
 * Add metadata to the packet
 *   IN:  | eth | ip | ...
 *   OUT: | eth | metadata | ip | ...
 * The function will create a clone of the complete buffer chain
 * and insert the given metadata as a new buffer in the cloned chain.
 * Untested and not used.
 *
 * @param[in] this
 *   Wrapper structure
 * @param[in] packet
 *   packet to add metadata to
 * @param[in] metadata
 *   metadata to add
 * @return
 *   The resulting packet.
 */
static struct rte_mbuf *
wrapper_add_data(struct rte_mempool *pool, struct rte_mbuf * packet,
								 struct wrapper_metadata * metadata) {
	// Fixed Offset where we slice the packet and insert the metadata.
	// Because we add the metadata after layer2,
	// this is the length of the ethernet header.
	const unsigned slice_offset = SLICE_OFFSET;
	unsigned offset = 0;

	// Clone the original packet
	packet = rte_pktmbuf_clone(packet, pool);

	// Walk thorugh segements until we reach the spot where we have to split
	while (slice_offset > offset + packet->data_len) {
		assert(packet != NULL);
		offset += packet->data_len;
		packet = packet->next;
	}

	struct rte_mbuf * buf_before = packet;
	struct rte_mbuf * buf_after  = NULL;

	if (slice_offset != offset + packet->data_len) {
		// Slice the packet
		struct rte_mbuf * buf_tail = rte_pktmbuf_alloc(pool);
		*buf_tail = *packet;
		rte_mbuf_refcnt_set(buf_tail, 1);
		rte_pktmbuf_adj(buf_tail, slice_offset - offset);
		packet->data_len = slice_offset - offset;
		buf_after = buf_tail;
	} else {
		// If slice_offset is in the middle of 2 chained buffers,
		// we can just insert the metadata in between
		assert(packet->next);
		buf_after = packet->next;
	}

	// Allocate buffer for metadata
	struct rte_mbuf * buf_metadata = rte_pktmbuf_alloc(pool);
	rte_memcpy(rte_pktmbuf_mtod(buf_metadata, void *), metadata, METADATA_LEN);
	buf_metadata->data_len = METADATA_LEN;

	// Insert metadata buffer in the buffer chain
	buf_before->next   = buf_metadata;
	buf_metadata->next = buf_after;

	return packet;
}

/**
 * Remove metadata from packet.
 * The buffer chain will be modified so the added metadata will
 * be exluded from the packet chain.
 * Untested and not used.
 *
 * @param[in] this
 *   Wrapper structure
 * @paran[in,out] packet
 *   packet to remove metadata from. This has to be a contigous packet.
 * @param[out] metadata
 *   metadata pointer to write metadata to
 */
static void
wrapper_remove_data(struct rte_mempool *pool, struct rte_mbuf *packet) {
	const unsigned slice_offset = SLICE_OFFSET;
	assert(rte_pktmbuf_is_contiguous(packet));

	struct rte_mbuf * buf_tail = rte_pktmbuf_alloc(pool);
	*buf_tail = *packet;

	packet->data_len = slice_offset;
	rte_pktmbuf_adj(buf_tail, slice_offset + METADATA_LEN);

	packet->next = buf_tail;
}

#endif /* WRAPPING_H_ */
