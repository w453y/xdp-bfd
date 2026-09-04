// SPDX-License-Identifier: GPL-2.0
/* bffdp.h - FRR distributed-BFD dataplane protocol.
 *
 * Adapted from FRR bfdd/bfddp_packet.h (MIT licensed,
 * Copyright (C) 2020 NetDEF, Rafael F. Zalamena). All fields are
 * network byte order; 64-bit fields big-endian.
 */
#ifndef BFD_ENGINE_BFFDP_H
#define BFD_ENGINE_BFFDP_H

#include <stddef.h>
#include <stdint.h>
#include <netinet/in.h>

/* ---------- bfddp protocol (from FRR bfddp_packet.h, MIT) ---------- */
enum bfddp_message_type {
	ECHO_REQUEST = 0,
	ECHO_REPLY = 1,
	DP_ADD_SESSION = 2,
	DP_DELETE_SESSION = 3,
	BFD_STATE_CHANGE = 4,
	DP_REQUEST_SESSION_COUNTERS = 5,
	BFD_SESSION_COUNTERS = 6,
};

/* Longest key the session message carries; must match bfdd's
 * BFDDP_AUTH_KEY_MAX or every authenticated ADD is misread. */
#define BFFDP_AUTH_KEY_MAX 64

/* How much of a session message has to be there.
 *
 * Authentication was appended to this message, so a control plane that
 * predates it sends a shorter one. The header carries the length and
 * that is the contract: anything from the start of the message up to
 * this point must be present, and everything after it is optional and
 * absent-means-unset. Requiring the whole struct instead would make
 * every ADD from an older daemon unparseable, and the failure would be
 * silence - no sessions, no error, nothing on the wire. */
#define BFFDP_SESSION_MSG_MIN offsetof(struct bfddp_session_msg, auth_type)

enum bfddp_session_flag {
	SESSION_MULTIHOP = (1 << 0),
	SESSION_DEMAND   = (1 << 1),
	SESSION_CBIT     = (1 << 2),
	SESSION_ECHO     = (1 << 3),
	SESSION_IPV6     = (1 << 4),
	SESSION_PASSIVE  = (1 << 5),
	SESSION_SHUTDOWN = (1 << 6),
};

/* Peer's bits as bfdd expects them in bfddp_state_change.remote_flags.
 * These are NOT the wire flag positions; see rflags_from_wire(). */
enum bfd_remote_flags {
	RBIT_CPI    = (1 << 0),
	RBIT_DEMAND = (1 << 1),
	RBIT_MP     = (1 << 2),
};

struct bfddp_message_header {
	uint8_t  version;      /* 1 */
	uint8_t  zero;
	uint16_t type;
	uint16_t id;           /* 0 = async */
	uint16_t length;       /* total, including this header */
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
	uint8_t  ttl;
	uint8_t  detect_mult;
	uint16_t zero;
	uint32_t ifindex;
	char     ifname[64];
	/* Authentication (RFC 5880 s6.7). Only the configuration crosses:
	 * the sequence numbers belong to whoever sends and receives, which
	 * for a delegated session is this engine. */
	uint8_t  auth_type;
	uint8_t  auth_keyid;
	uint8_t  auth_keylen;
	uint8_t  auth_zero;
	char     auth_key[BFFDP_AUTH_KEY_MAX];
} __attribute__((packed));

struct bfddp_state_change {
	uint32_t lid;
	uint32_t rid;
	uint32_t remote_flags;
	uint32_t desired_tx;
	uint32_t required_rx;
	uint32_t required_echo_rx;
	uint8_t  state;
	uint8_t  diagnostics;
	uint8_t  detection_multiplier;
} __attribute__((packed));

struct bfddp_counters {
	uint32_t lid;
	uint32_t pad;   /* FRR struct is unpacked: u64s are 8-aligned */
	uint64_t control_input_bytes;
	uint64_t control_input_packets;
	uint64_t control_output_bytes;
	uint64_t control_output_packets;
	uint64_t echo_input_bytes;
	uint64_t echo_input_packets;
	uint64_t echo_output_bytes;
	uint64_t echo_output_packets;
} __attribute__((packed));

#endif /* BFD_ENGINE_BFFDP_H */
