#include "indextable.h"
#include "init.h"

#include <assert.h>
#include <string.h>

#include <rte_malloc.h>
#include <rte_mbuf.h>
#include <rte_hash_crc.h>
#include <rte_jhash.h>
#include <rte_cycles.h>
#include <rte_log.h>

#define RTE_LOGTYPE_INDEXTABLE RTE_LOGTYPE_USER1

/**
 * Calculates the index of a given packet.
 *
 * @return
 *    the index of a given packet in [0, this->nb_buckets)
 */
static inline unsigned
indextable_hash(struct indextable *this, struct rte_mbuf *packet) {

	// Strip ethernet adresses for calculation because it will change through
	// the firewalls
	uint8_t *data = rte_pktmbuf_mtod_offset(packet, uint8_t *, 2* sizeof(struct ether_addr));

#if HASH_FUNC == HASH_JHASH
		return (rte_jhash(data, packet->data_len - 2* sizeof(struct ether_addr), 0xFFFFFFFF));
#endif

#if HASH_FUNC == HASH_CRC32
		return (rte_hash_crc(data, packet->data_len - 2* sizeof(struct ether_addr), 0));
#endif
}

/**
 * Compares 2 packets
 *
 * @param[in] packet1
 *   First packet
 * @param[in] packet2
 *   Second packet
 * @return
 *  TRUE if the packets are equal
 */
static inline int
indextable_compare(struct rte_mbuf *packet1, struct rte_mbuf *packet2) {
	if (packet1->data_len != packet2->data_len) {
		return FALSE;
	}
	// skip ethernet addresses
	uint8_t *data1 = rte_pktmbuf_mtod_offset(packet1, uint8_t *, 2* sizeof(struct ether_addr));
	uint8_t *data2 = rte_pktmbuf_mtod_offset(packet2, uint8_t *, 2* sizeof(struct ether_addr));

	return memcmp(data1, data2, packet1->data_len - 2* sizeof(struct ether_addr)) == 0;
}


struct indextable *
indextable_create(unsigned nb_buckets, unsigned nb_entries_per_bucket) {

	// Allocate the storage.
	void *memory = rte_zmalloc(NULL, sizeof(struct indextable) +
		sizeof(struct indextable_entry) * nb_buckets * nb_entries_per_bucket, 64);

	if (unlikely(memory == NULL)) {
		RTE_LOG(ERR, INDEXTABLE, "Cannot allocate memory for indextable");
		die();
	}

	struct indextable *this = (struct indextable *) memory;

	this->entries               = (memory + sizeof(struct indextable));
	this->nb_buckets            = nb_buckets;
	this->nb_entries_per_bucket = nb_entries_per_bucket;
	this->replaced_entries      = 0;
	this->nb_entries_used       = 0;

	// Initialize the entries.
	unsigned nb_entries = this->nb_buckets * this->nb_entries_per_bucket;
	for (unsigned i = 0; i < nb_entries; i++) {
		struct indextable_entry *entry = &this->entries[i];

		entry->packet = NULL;
	}

	return this;
}


void
indextable_destroy(struct indextable *this) {
	unsigned nb_entries = this->nb_buckets * this->nb_entries_per_bucket;
	for (unsigned i = 0; i < nb_entries; i++) {
		struct indextable_entry *entry = &this->entries[i];
		
		if (entry->packet != NULL) {
			struct rte_mbuf * buf = entry->packet;
			indextable_delete(this, entry);
			rte_pktmbuf_free(buf);
		}
	}
	rte_free(this);
}


void
indextable_delete(struct indextable *this, struct indextable_entry * entry) {
	// Skip freeing the packet if not existing.
	if (unlikely(entry->packet == NULL)) {
		return;
	}

	uint16_t refcnt = rte_mbuf_refcnt_read(entry->packet);
	if (unlikely(refcnt > 1)) {
		//die();
		rte_mbuf_refcnt_update(entry->packet, -1);
	} else if (likely(refcnt == 1)) {
		rte_pktmbuf_free(entry->packet);
	}

	// Set it to NULL to prevent double free
	entry->packet = NULL;

	this->nb_entries_used--;

	return;
}


struct indextable_entry *
indextable_put(struct indextable *this, struct rte_mbuf *packet) {
	// Get the first entry of the corresonding bucket
	uint32_t hash_crc = indextable_hash(this, packet);
	unsigned hash     = hash_crc % this->nb_buckets;
	struct indextable_entry *bucket = indextable_get_bucket(this, hash);
	struct indextable_entry *entry  = NULL;

	//stat_put_entropy_index(hash);

	// If the Bucket is full, we choose the oldest packet
	// with the least answers
	
	struct indextable_entry *replace;
	uint64_t min_time = 0xFFFFFFFFFFFFFFFF;
	unsigned min_recv = 100000;
	
	for (int i = 0; i < this->nb_entries_per_bucket; i++) {
		entry = &bucket[i];

		if (likely(entry->packet == NULL || entry->received == INDEXTABLE_CAN_BE_DELETED)) {
			indextable_delete(this, entry);
			break;
		}
		
		if (likely(entry->received < min_recv)) {
			min_recv = entry->received;
			replace  = entry;
		} else if (entry->received_time < min_time) {
			min_time = entry->received_time;
			replace  = entry;
		}
	}
	
	// Check if we got an empty entry
	if (unlikely(entry->packet != NULL)) {
		assert(entry->received != INDEXTABLE_CAN_BE_DELETED);
		assert(replace->received != INDEXTABLE_CAN_BE_DELETED);
		assert(replace->packet != NULL);
		entry = replace;
		rte_mbuf_refcnt_update(entry->packet, -1);
		indextable_delete(this, entry);
		this->replaced_entries++;
	}

	// Set the values of the new entry.
	entry->packet           = packet;
	entry->received         = 0;
	entry->received_time    = rte_get_tsc_cycles();
	entry->hash_crc         = hash_crc;

	// Increase the reference counter to prevent the packet being freed when sent.
	// It needs to be freed in the delete_index_table_entry()-function.
	rte_pktmbuf_refcnt_update(entry->packet, 1);

	this->nb_entries_used++;

	return entry;
}


struct indextable_entry *
indextable_get(struct indextable *this, struct rte_mbuf *packet) {
	// Get the first entry of the corresonding bucket
	unsigned hash = indextable_hash(this, packet) % this->nb_buckets;
	struct indextable_entry *entry = indextable_get_bucket(this, hash);
	
	for (int i = 0; i < this->nb_entries_per_bucket; i++) {
		if (entry->packet != NULL && indextable_compare(entry->packet, packet)) {
			return entry;
		}
		entry++;
	}
	
	return NULL;
}
