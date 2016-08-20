/**
 * An index table stores information about packets received from one of the
 * connected networks and the current state of the forwarding decision.
 *
 * An index table consists of nb_buckets buckets with space for 
 * nb_entries_per_bucket per bucket. Packets will be hashed and stored
 * in the bucket with number hash(packet) % nb_buckets.
 *
 * @file index_table.h
 * @author Matthias Drexler
 * @author Philipp Jeitner
 * @date 3 Dec 2015
 */

#ifndef INDEXTABLE_H_
#define INDEXTABLE_H_

#include <rte_mbuf.h>
#include "components/wrapping.h"

/**
 * Hash Function to use
 * valid values are: HASH_CRC32, HASH_JHASH
 */
#define HASH_CRC32 1
#define HASH_JHASH 2
#define HASH_FUNC HASH_CRC32

#if HASH_FUNC != HASH_CRC32
#pragma message "Wrapper Compression won't work when HASH_FUNC != HASH_CRC32"
#endif

/**
 * Defines an invalid index in the Table
 */
#define INDEXTABLE_INVALID_INDEX (0xFFFFFFFF + 1)

#define INDEXTABLE_CAN_BE_DELETED 0xFFFF

/**
 * The entry where information about the packets destined for the firewall
 * network are stored.
 *
 * If N firewalls are used in the system, N index_table_entries belong to one
 * packet entry.
 *
 * packet:
 *    The corresponding packet for which the forwarding decision is made.
 * received:
 *    The number the firewall with the associated firewall-ID has forwarded
 *    the packet.
 * firewall:
 *    Firewalls from which the forwarding decision is already received are
 *    marked in this array to prevent receiving a decision multiple times.
 */
struct indextable_entry {
	struct rte_mbuf *packet;
	uint32_t hash_crc;
	struct metadata_t meta;
	unsigned received;
	uint64_t received_time;

	// Used for SHA256 etc
	unsigned char data[64];
};

/**
 * Index Table base structure
 */
struct indextable {
	unsigned firewall_count;
	unsigned nb_buckets;
	unsigned nb_entries_per_bucket;
	unsigned nb_entries_used;
	
	struct indextable_entry * entries;

	// Stats
	unsigned long replaced_entries;
};

/**
 * Creates an index table and allocates memory for it.
 *
 * It is guaranteed that the packet member of the indextable_entry
 * structures will be NULL.
 *
 * @param[in] nb_buckets
 *    Number of buckets in the internal hashtable
 * @param[in] nb_entries_per_bucket
 *    Number of entries per bucket
 * @return
 *    The created indextable
 */
struct indextable *
indextable_create(unsigned nb_buckets, unsigned nb_entries_per_bucket);

/**
 * Destroys the index table and deallocates all Memory.
 *
 * @param[in] this
 *    The indextable
 */
void
indextable_destroy(struct indextable *);

/**
 * Create new index table entries for the given packet.
 *
 * The index where the new index table entries are placed are determined by
 * the hash of the packet contents.
 * The index where the entry was created is set as value of the index-parameter.
 *
 * @param[in] this
 *    The indextable
 * @param[in] packet
 *    The packet to store
 * @return
 *    Index of the created entry
 *    INDEXTABLE_INVALID_INDEX if the entry could not be created
 */
struct indextable_entry *
indextable_put(struct indextable *indextable, struct rte_mbuf *packet);

/**
 * Returns the index table entry for the given packet
 *
 * @param[in] this
 *    The indextable
 * @param[in] packet
 *    Packet to search
 * @return
 *    NULL if the packet is not found
 */
struct indextable_entry *
indextable_get(struct indextable *indextable, struct rte_mbuf *packet);

/**
 * Deletes the index table entry at the given index.
 *
 * The refcnt of the packet will be decreased, but the packet will not be freed.
 *
 * @param[in] indextable
 *    The indextable
 * @param[in] entry
 *    Entry to be deleted
 */
void
indextable_delete(struct indextable *indextable, struct indextable_entry * entry);

/**
 * Returns the First entry in the bucket with the hash value hash
 * 
 * @param[in] hash
 *   Hash value of the bucket to find
 * @return
 *   The first entry of the bucket
 */
static inline struct indextable_entry *
indextable_get_bucket(struct indextable *this, unsigned hash) {
	return &this->entries[hash * this->nb_entries_per_bucket];
}

#endif /* INDEXTABLE_H_ */
