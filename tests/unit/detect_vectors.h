/* SPDX-License-Identifier: GPL-2.0 */
/*
 * detect_vectors.h - vectors for the poll-aware detect rule, which exists
 * in fsm.c and in bfd_xdp.c; both must agree on every vector.
 *
 * The candidate differs deliberately: fsm.c takes max(r_min_tx,
 * min_rx_us), bfd_xdp.c clamps the wire min_tx to cfg->min_rx_us or
 * LOCAL_MIN_RX_US. Boundary vectors (gap == candidate) are engine-only,
 * since the XDP driver's synthesised gap carries clock skew.
 */
#ifndef DETECT_VECTORS_H
#define DETECT_VECTORS_H

#include <stdint.h>

#define DV_MAX_STEPS 4

struct dv_step {
        uint32_t adv_min_tx_us; /* what the peer advertises in this packet */
        uint32_t gap_us;        /* since the previous packet; 0 = first */
        uint32_t want_iv_us;    /* expected detect_iv_us after this packet */
};

struct dv_case {
        const char *name;
        uint32_t local_min_rx_us;   /* our required RX, the candidate floor */
        int boundary;               /* 1 = engine-only, see header comment */
        int nsteps;
        struct dv_step steps[DV_MAX_STEPS];
};

/* Every case starts from a session with no prior interval, so step 0
 * always takes the candidate unconditionally. */
static const struct dv_case dv_cases[] = {
        { "first-packet-takes-candidate", 10000, 0, 1, {
                { 10000, 0, 10000 },
        } },

        /* Increases are always safe: a larger interval is a larger
         * budget, so it applies on the packet that advertises it. */
        { "increase-applies-immediately", 10000, 0, 2, {
                { 10000,     0, 10000 },
                { 50000, 10000, 50000 },
        } },

        /* Decreases wait for pacing. The packet that advertises 5ms
         * still arrives 50ms after the last one, so the gap does not
         * fit and the old interval holds. */
        { "decrease-held-until-paced", 10000, 0, 3, {
                { 50000,     0, 50000 },
                {  5000, 50000, 50000 },
                {  5000,  5000, 10000 },
        } },

        /* The candidate floor: our own min_rx wins when the peer
         * advertises below it. 5000 advertised against a 10000 floor
         * is a candidate of 10000, not 5000. */
        { "candidate-floors-at-local-min-rx", 10000, 0, 1, {
                { 5000, 0, 10000 },
        } },

        /* A gap far under the candidate confirms pacing at once. */
        { "decrease-applies-when-well-paced", 5000, 0, 3, {
                { 40000,     0, 40000 },
                {  5000, 40000, 40000 },
                {  5000,  1000,  5000 },
        } },

        /* Boundary: gap exactly equal to the candidate. The engine
         * comparison is <=, so this accepts. Engine-only. */
        { "decrease-at-exact-gap-accepts", 5000, 1, 3, {
                { 40000,     0, 40000 },
                {  5000, 40000, 40000 },
                {  5000,  5000,  5000 },
        } },

        /* Boundary: one microsecond over. Must not accept. */
        { "decrease-one-over-gap-holds", 5000, 1, 3, {
                { 40000,     0, 40000 },
                {  5000, 40000, 40000 },
                {  5000,  5001, 40000 },
        } },
};

#define DV_NCASES ((int)(sizeof(dv_cases) / sizeof(dv_cases[0])))

#endif /* DETECT_VECTORS_H */
