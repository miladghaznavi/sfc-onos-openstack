#include "d_list.h"

#include <inttypes.h>
#include <stdlib.h>
#include <stdio.h>

static void
link(struct d_list_t* first, struct d_list_t* second) {
	second->prev = first;
    first->next = second;
}

struct d_list_t *
d_list_insert_front(struct d_list_t* d_list, void* item) {
    struct d_list_t *new = malloc(sizeof(struct d_list_t));
    struct d_list_t *prev = d_list->prev;

    link(prev, new);
    link(new, d_list);
    new->item = item;

    return new;
}

struct d_list_t *
d_list_insert_back(struct d_list_t* d_list, void* item) {
    struct d_list_t *new = malloc(sizeof(struct d_list_t));
    struct d_list_t *next = d_list->next;
    
    link(d_list, new);
    link(new, next);
    new->item = item;

    return new;
}

void*
d_list_remove(struct d_list_t *d_list) {
	if (d_list == NULL) return NULL;

	if (d_list->prev != NULL && d_list->next != NULL) {
    	link(d_list->prev, d_list->next);

	} else if (d_list->prev == NULL) {
		d_list->next->prev = NULL;

	} else if (d_list->next == NULL) {
		d_list->prev->next = NULL;
	}
	void *item = d_list->item;
	d_list->prev = NULL;
	d_list->next = NULL;
	free(d_list);
	return item;
}

struct d_list_t *
d_list_head(struct d_list_t *d_list) {
    struct d_list_t *head = d_list;
    while (head->prev != NULL) {
        head = head->prev;
    }
    return head;
}

struct d_list_t *
d_list_tail(struct d_list_t *d_list) {
    struct d_list_t *tail = d_list;
    while (tail->next != NULL) {
        tail = tail->next;
    }
    return tail;
}

unsigned
d_list_len(struct d_list_t *d_list) {
	if (d_list == NULL) return 0;

	unsigned len = 1;
	struct d_list_t *next = d_list_head(d_list);
	
	while ((next = next->next) != NULL) {
		len++;
	}
	return len;
}

void
d_list_print(struct d_list_t *d_list) {
    struct d_list_t *next = d_list_head(d_list);
    
    printf("[");
    while (next != NULL) {
        printf("%p, ", next->item);
        next = next->next;
    }
    printf("]\n");
}
