/**
 * Double linked list
 */

#ifndef D_LIST_H_
#define D_LIST_H_

struct d_list_t {
    struct d_list_t *prev;
    struct d_list_t *next;
    void *item;
};

struct d_list_t *
d_list_insert_front(struct d_list_t *d_list, void *item);

struct d_list_t *
d_list_insert_back(struct d_list_t *d_list, void *item);

void *
d_list_remove(struct d_list_t *d_list);

unsigned
d_list_len(struct d_list_t *d_list);

struct d_list_t *
d_list_head(struct d_list_t *d_list);

struct d_list_t *
d_list_tail(struct d_list_t *d_list);

void
d_list_print(struct d_list_t *d_list);

#endif
