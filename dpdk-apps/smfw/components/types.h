#ifndef BENCH_TYPES_H_
#define BENCH_TYPES_H_

#include <inttypes.h>

typedef uint64_t second_t;

typedef uint64_t m_second_t;

typedef uint64_t u_second_t;

typedef uint64_t n_second_t;

static inline second_t
ms_to_s(m_second_t ms) {
    return (second_t) ms / 1000;
}

static inline m_second_t
us_to_ms(u_second_t us) {
    return (m_second_t) us / 1000;
}

static inline u_second_t
ns_to_us(n_second_t ns) {
    return (u_second_t) ns / 1000;
}

static inline second_t
s_to_ms(second_t s) {
    return (m_second_t) s * 1000;
}

static inline u_second_t
ms_to_us(m_second_t us) {
    return (u_second_t) us * 1000;
}

static inline n_second_t
us_to_ns(u_second_t ns) {
    return (n_second_t) ns * 1000;
}

#endif /* BENCH_TYPES_H_ */
