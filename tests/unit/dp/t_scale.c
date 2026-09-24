// SPDX-License-Identifier: GPL-2.0
/* Part of dp_run.c. */

static void scale_addrs(int i, char *l, char *p, size_t n)
{
	snprintf(l, n, "10.1.%d.%d", i / 250, 1 + i % 250);
	snprintf(p, n, "10.2.%d.%d", i / 250, 1 + i % 250);
}

/* The whole table through bfddp: every session found by each of its keys, the
 * one past the table refused, and none left after the deletes.
 */
static void case_table_fills(void)
{
	unsigned char buf[256];
	char l[32], p[32];
	int bad = 0, found = 0;

	if (!rig_up()) {
		report("table-fills", 1, "rig setup failed");
		rig_down();
		return;
	}
	sessions_clear();
	for (int i = 0; i <= sess_max; i++) {
		scale_addrs(i, l, p, sizeof(l));
		feed(buf, build_add(buf, 0x10000 + i, l, p));
		dp_read();
	}
	if (used_sessions() != sess_max) {
		printf("     %d sessions, want the table's %d\n", used_sessions(), sess_max);
		bad = 1;
	}
	if (sess_by_lid(0x10000 + sess_max)) {
		printf("     the ADD past the table was taken\n");
		bad = 1;
	}
	for (int i = 0; i < sess_max; i++) {
		struct session *s = sess_by_lid(0x10000 + i);

		if (s && sess_by_wire(s->wire_disc) == s && sess_by_addr(&s->peer, &s->local) == s)
			found++;
	}
	if (found != sess_max) {
		printf("     %d of %d found by lid, discriminator and pair\n", found, sess_max);
		bad = 1;
	}

	for (int i = 0; i < sess_max; i++) {
		struct bfddp_message_header *h = (void *)buf;
		size_t n;

		scale_addrs(i, l, p, sizeof(l));
		n = build_add(buf, 0x10000 + i, l, p);
		h->type = htons(DP_DELETE_SESSION);
		feed(buf, n);
		dp_read();
	}
	if (used_sessions()) {
		printf("     %d sessions left after deleting all\n", used_sessions());
		bad = 1;
	}
	rig_down();
	report("table-fills", bad, "every key finds its session; one past is refused");
}
