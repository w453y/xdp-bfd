// SPDX-License-Identifier: GPL-2.0
/* Part of dp_run.c. */

static void idx_addr(struct bfd_addr *a, unsigned int v)
{
	memset(a, 0, sizeof(*a));
	a->b[10] = a->b[11] = 0xff;
	a->b[14] = (uint8_t)(v >> 8);
	a->b[15] = (uint8_t)v;
}

static int idx_agree(struct session *got, int found, const char *what, unsigned int v)
{
	if (!!got == found)
		return 0;
	printf("     %s %u: cache says %s, scan says %s\n", what, v, got ? "found" : "absent",
	       found ? "found" : "absent");
	return 1;
}

/* The lookups against a plain scan, through adds, key changes with and without
 * sess_reindex, and frees: the cache may be stale, never wrong.
 */
static void case_index_matches_scan(void)
{
	unsigned int seed = 1;
	int bad = 0;

	sessions_clear();
	for (int op = 0; op < 20000 && !bad; op++) {
		struct session *s = &sessions[rand_r(&seed) % MAX_SESSIONS];
		int kind = rand_r(&seed) % 4;

		if (kind == 3) {
			memset(s, 0, sizeof(*s));
		} else {
			s->used = 1;
			s->lid = 1 + rand_r(&seed) % 3000;
			s->wire_disc = 1 + rand_r(&seed) % 3000;
			idx_addr(&s->peer, rand_r(&seed) % 3000);
			idx_addr(&s->local, 7);
			if (kind != 2)
				sess_reindex(s);
		}

		unsigned int v = 1 + rand_r(&seed) % 3000;
		struct bfd_addr p, l;
		int lid = 0, wire = 0, pair = 0;

		idx_addr(&p, v);
		idx_addr(&l, 7);
		for (int i = 0; i < MAX_SESSIONS; i++) {
			const struct session *o = &sessions[i];

			if (!o->used)
				continue;
			lid |= o->lid == v;
			wire |= o->wire_disc == v;
			pair |= !memcmp(&o->peer, &p, 16) && !memcmp(&o->local, &l, 16);
		}
		bad |= idx_agree(sess_by_lid(v), lid, "lid", v);
		bad |= idx_agree(sess_by_wire(v), wire, "wire_disc", v);
		bad |= idx_agree(sess_by_addr(&p, &l), pair, "peer", v);

		struct session *g = sess_by_lid(v);

		if (g && g->lid != v) {
			printf("     lid %u: returned lid %u\n", v, g->lid);
			bad = 1;
		}
	}
	sessions_clear();
	report("index-matches-scan", bad, "20000 random operations");
}
