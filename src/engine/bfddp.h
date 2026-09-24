// SPDX-License-Identifier: GPL-2.0
/* bfddp.h - FRR's distributed-BFD protocol, from bfdd/bfddp_packet.h (MIT,
 * Copyright (C) 2020 NetDEF, Rafael F. Zalamena). Network byte order.
 */
#ifndef BFD_ENGINE_BFDDP_H
#define BFD_ENGINE_BFDDP_H

#include <stddef.h>
#include <stdint.h>
#include <netinet/in.h>

enum bfddp_message_type {
	ECHO_REQUEST = 0,
	ECHO_REPLY = 1,
	DP_ADD_SESSION = 2,
	DP_DELETE_SESSION = 3,
	BFD_STATE_CHANGE = 4,
	DP_REQUEST_SESSION_COUNTERS = 5,
	BFD_SESSION_COUNTERS = 6,
	DP_SESSION_AUTH = 7,
};

/* Must match bfdd's BFDDP_AUTH_KEY_MAX. */
#define BFDDP_AUTH_KEY_MAX 64

/* Must match bfdd's BFDDP_AUTH_KEY_COUNT_MAX. Declared in full so a message
 * reads in place.
 */
#define BFDDP_AUTH_KEY_COUNT_MAX 16

#define BFDDP_SESSION_MSG_MIN sizeof(struct bfddp_session_msg)

enum bfddp_session_flag {
	SESSION_MULTIHOP = (1 << 0),
	SESSION_DEMAND = (1 << 1),
	SESSION_CBIT = (1 << 2),
	SESSION_ECHO = (1 << 3),
	SESSION_IPV6 = (1 << 4),
	SESSION_PASSIVE = (1 << 5),
	SESSION_SHUTDOWN = (1 << 6),
	/* Keys follow in DP_SESSION_AUTH; clearing it withdraws them. */
	SESSION_AUTH = (1 << 7),
};

/* Not the wire positions; see rflags_from_wire(). */
enum bfd_remote_flags {
	RBIT_CPI = (1 << 0),
	RBIT_DEMAND = (1 << 1),
	RBIT_MP = (1 << 2),
};

struct bfddp_message_header {
	uint8_t version; /* 1 */
	uint8_t zero;
	uint16_t type;
	uint16_t id;	 /* 0 = async */
	uint16_t length; /* total, including this header */
} __attribute__((packed));

struct bfddp_echo {
	uint64_t dp_time;
	uint64_t bfdd_time;
} __attribute__((packed));

struct bfddp_session_msg {
	uint32_t flags;
	struct in6_addr src;
	struct in6_addr dst;
	uint32_t lid;
	uint32_t min_tx;
	uint32_t min_rx;
	uint32_t min_echo_tx;
	uint32_t min_echo_rx;
	uint32_t hold_time;
	uint8_t ttl;
	uint8_t detect_mult;
	uint16_t zero;
	uint32_t ifindex;
	char ifname[64];
} __attribute__((packed));

/* Epoch seconds; start 0 means always, end -1 never. */
struct bfddp_key_lifetime {
	int64_t start;
	int64_t end;
} __attribute__((packed));

/* Sending stops before accepting does, so in-flight packets verify during a
 * rollover.
 */
struct bfddp_auth_key {
	uint8_t type;
	uint8_t key_id;
	uint8_t key_len;
	uint8_t zero[5];
	struct bfddp_key_lifetime send;
	struct bfddp_key_lifetime accept;
	char key[BFDDP_AUTH_KEY_MAX];
} __attribute__((packed));

/* Only key_count entries are on the wire. */
struct bfddp_session_auth {
	uint32_t lid;
	uint16_t key_count;
	uint16_t zero;
	struct bfddp_auth_key keys[BFDDP_AUTH_KEY_COUNT_MAX];
} __attribute__((packed));

#define BFDDP_SESSION_AUTH_MIN offsetof(struct bfddp_session_auth, keys)

struct bfddp_state_change {
	uint32_t lid;
	uint32_t rid;
	uint32_t remote_flags;
	uint32_t desired_tx;
	uint32_t required_rx;
	uint32_t required_echo_rx;
	uint8_t state;
	uint8_t diagnostics;
	uint8_t detection_multiplier;
} __attribute__((packed));

struct bfddp_counters {
	uint32_t lid;
	uint32_t pad; /* FRR struct is unpacked: u64s are 8-aligned */
	uint64_t control_input_bytes;
	uint64_t control_input_packets;
	uint64_t control_output_bytes;
	uint64_t control_output_packets;
	uint64_t echo_input_bytes;
	uint64_t echo_input_packets;
	uint64_t echo_output_bytes;
	uint64_t echo_output_packets;
} __attribute__((packed));

#endif /* BFD_ENGINE_BFDDP_H */
