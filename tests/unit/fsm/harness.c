// SPDX-License-Identifier: GPL-2.0
/* Part of fsm_run, split by subject; compiled as one unit via
 * tests/unit/fsm_run.c.
 */

/* Sessions must live in the global array: fsm.c derives a slot index from the
 * pointer. Every case uses slot 0.
 */
#define TEST_SLOT 0

/* A session in a chosen state with the peer known; 10ms timers. */
static struct session *sess_init(uint8_t state)
{
	struct session *s = &sessions[TEST_SLOT];

	memset(s, 0, sizeof(*s));
	s->used = 1;
	s->lid = 0x11111111;
	s->wire_disc = s->lid;
	s->state = state;
	s->min_tx_us = 10000;
	s->applied_tx_us = 10000;
	s->min_rx_us = 10000;
	s->detect_mult = 3;
	s->r_min_tx = 10000;
	s->r_min_rx = 10000;
	s->r_mult = 3;
	s->detect_iv_us = 10000;
	s->last_rx_us = 1000000;
	return s;
}

static struct bfd_ctrl_pkt pkt(uint8_t peer_state, uint8_t extra_flags)
{
	struct bfd_ctrl_pkt p = { 0 };

	p.vers_diag = 1 << 5;
	p.flags = (peer_state << 6) | extra_flags;
	p.detect_mult = 3;
	p.len = 24;
	p.my_disc = htonl(0x22222222);
	p.your_disc = htonl(0x11111111);
	p.min_tx = htonl(10000);
	p.min_rx = htonl(10000);
	return p;
}

static const char *st_name(uint8_t s)
{
	switch (s) {
	case ST_ADMINDOWN:
		return "AdminDown";
	case ST_DOWN:
		return "Down";
	case ST_INIT:
		return "Init";
	case ST_UP:
		return "Up";
	default:
		return "?";
	}
}

/* Send hook that refuses every datagram. */
static ssize_t refuse_send(int fd, const void *buf, size_t len, const struct sockaddr *dst,
			   socklen_t dlen)
{
	(void)fd;
	(void)buf;
	(void)len;
	(void)dst;
	(void)dlen;
	errno = EPERM;
	return -1;
}

/* Captures what tx_one would have sent. */
static __u8 sent_buf[BFD_MAX_LEN];
static size_t sent_len;
static int sent_calls;

static ssize_t capture_send(int fd, const void *buf, size_t len, const struct sockaddr *dst,
			    socklen_t dlen)
{
	(void)fd;
	(void)dst;
	(void)dlen;
	sent_len = len > sizeof(sent_buf) ? sizeof(sent_buf) : len;
	memcpy(sent_buf, buf, sent_len);
	sent_calls++;
	return (ssize_t)len;
}
