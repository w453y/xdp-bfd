// SPDX-License-Identifier: GPL-2.0
/* Part of dp_run.c. */

static int cli = -1; /* our end, standing in for bfdd */
static char sockpath[64];

static int rig_up(void)
{
	snprintf(sockpath, sizeof(sockpath), "/tmp/dp_run.%d.sock", getpid());
	unlink(sockpath);

	if (dp_listen_init(sockpath)) {
		printf("     dp_listen_init failed\n");
		return 0;
	}

	cli = socket(AF_UNIX, SOCK_STREAM, 0);
	if (cli < 0) {
		printf("     socket: %s\n", strerror(errno));
		return 0;
	}

	struct sockaddr_un sa = { .sun_family = AF_UNIX };

	strncpy(sa.sun_path, sockpath, sizeof(sa.sun_path) - 1);
	if (connect(cli, (void *)&sa, sizeof(sa))) {
		printf("     connect: %s\n", strerror(errno));
		return 0;
	}

	dp_accept(); /* the engine's own accept path installs dp_conn */
	return 1;
}

static void rig_down(void)
{
	if (cli >= 0)
		close(cli);
	cli = -1;
	unlink(sockpath);
}

/* Without reaching into dplane.c. */
static int conn_alive(void)
{
	int l = -1, c = -1;

	dp_fds(&l, &c);
	return c >= 0;
}

static int used_sessions(void)
{
	int n = 0;

	for (int i = 0; i < sess_max; i++)
		if (sessions[i].used)
			n++;
	return n;
}

static void sessions_clear(void)
{
	memset(sessions, 0, (size_t)sess_max * sizeof(*sessions));
}

/* bfddp carries both families as in6_addr; v4 in the first four bytes. */
static size_t build_add(unsigned char *buf, uint32_t lid, const char *local, const char *peer)
{
	struct bfddp_message_header *h = (void *)buf;
	struct bfddp_session_msg *s = (void *)(h + 1);
	size_t len = sizeof(*h) + sizeof(*s);

	memset(buf, 0, len);
	h->version = 1;
	h->type = htons(DP_ADD_SESSION);
	h->length = htons((uint16_t)len);

	s->lid = htonl(lid);
	s->flags = htonl(0); /* v4: SESSION_IPV6 clear */
	{
		uint32_t a = inet_addr(local), b = inet_addr(peer);

		memcpy(&s->src.s6_addr[0], &a, 4);
		memcpy(&s->dst.s6_addr[0], &b, 4);
	}
	s->min_tx = htonl(10000);
	s->min_rx = htonl(10000);
	s->ttl = 255;
	s->detect_mult = 3;
	return len;
}

/* A separate branch of sm_addrs. */
static size_t build_add6(unsigned char *buf, uint32_t lid, const char *local, const char *peer)
{
	struct bfddp_message_header *h = (void *)buf;
	struct bfddp_session_msg *s = (void *)(h + 1);
	size_t len = sizeof(*h) + sizeof(*s);

	memset(buf, 0, len);
	h->version = 1;
	h->type = htons(DP_ADD_SESSION);
	h->length = htons((uint16_t)len);

	s->lid = htonl(lid);
	s->flags = htonl(SESSION_IPV6);
	inet_pton(AF_INET6, local, &s->src);
	inet_pton(AF_INET6, peer, &s->dst);
	s->min_tx = htonl(10000);
	s->min_rx = htonl(10000);
	s->ttl = 255;
	s->detect_mult = 3;
	return len;
}

static void feed(const void *p, size_t n)
{
	if (write(cli, p, n) != (ssize_t)n)
		printf("     short write: %s\n", strerror(errno));
}

/* An ADD that says the session authenticates. */
static size_t build_add_auth(unsigned char *buf, uint32_t lid, const char *local, const char *peer)
{
	struct bfddp_message_header *h = (void *)buf;
	struct bfddp_session_msg *s = (void *)(h + 1);
	size_t len = build_add(buf, lid, local, peer);

	s->flags = htonl(SESSION_AUTH);
	(void)h;
	return len;
}

/* Key 1 sends to 2000 and is accepted to 3000; key 2 is accepted from 1500. */
static size_t build_session_auth(unsigned char *buf, uint32_t lid)
{
	struct bfddp_message_header *h = (void *)buf;
	struct bfddp_session_auth *a = (void *)(h + 1);
	size_t len = sizeof(*h) + offsetof(struct bfddp_session_auth, keys) +
		     2 * sizeof(a->keys[0]);

	memset(buf, 0, len);
	h->version = 1;
	h->type = htons(DP_SESSION_AUTH);
	h->length = htons((uint16_t)len);

	a->lid = htonl(lid);
	a->key_count = htons(2);

	a->keys[0].type = BFD_AUTH_KEYED_SHA1;
	a->keys[0].key_id = 1;
	a->keys[0].key_len = 8;
	memcpy(a->keys[0].key, "firstkey", 8);
	a->keys[0].send.start = htobe64(1000);
	a->keys[0].send.end = htobe64(2000);
	a->keys[0].accept.start = htobe64(1000);
	a->keys[0].accept.end = htobe64(3000);

	a->keys[1].type = BFD_AUTH_KEYED_SHA1;
	a->keys[1].key_id = 2;
	a->keys[1].key_len = 9;
	memcpy(a->keys[1].key, "secondkey", 9);
	a->keys[1].send.start = htobe64(2001);
	a->keys[1].send.end = htobe64(4000);
	a->keys[1].accept.start = htobe64(1500);
	a->keys[1].accept.end = htobe64(4000);

	return len;
}
