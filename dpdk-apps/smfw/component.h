#ifndef COMPONENT_H_
#define COMPONENT_H_

struct receiver {
    void (*receive_mbuf) (struct rte_mbuf *m);
};

#endif /* COMPONENT_H_ */
