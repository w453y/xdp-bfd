// SPDX-License-Identifier: GPL-2.0
/* Part of xdp_run.c. */

static int changes_seen;

static int on_change_ev(void *ctx, void *data, size_t len)
{
	const struct bfd_event *e = data;

	(void)ctx;
	if (len >= sizeof(*e) && e->event == BFD_EV_CHANGED)
		changes_seen++;
	return 0;
}

/* Events on bfd_changes after one frame. */
static int changes_after(struct ring_buffer *rb, const struct frame *f)
{
	/* Past the program's one-per-CHANGE_MIN_NS window. */
	usleep(2000);
	ring_buffer__consume(rb);
	changes_seen = 0;
	run_frame(f, NULL, NULL);
	ring_buffer__consume(rb);
	return changes_seen;
}

/* The program says when something the engine mirrors moved, and only then:
 * the engine no longer reads the map every pass.
 */
static void case_change_events(void)
{
	struct session_key k = key_v4("10.0.0.2", "10.0.0.1");
	struct bfd_ctrl_pkt p = ctrl_up();
	struct ring_buffer *rb;
	struct tx_cfg cfg;
	struct frame f;
	int n, bad = 0;

	rb = changes_fd >= 0 ? ring_buffer__new(changes_fd, on_change_ev, NULL, NULL) : NULL;
	if (!rb) {
		printf("FAIL %-40s no bfd_changes ring\n", "change-events");
		fails++;
		return;
	}
	map_reset();
	arm_session();
	bpf_map_delete_elem(sess_fd, &k);

	build_v4(&f, 255, BFD_PORT_1HOP, &p, 0);
	n = changes_after(rb, &f);
	if (n != 1) {
		printf("     first packet: %d events, want 1\n", n);
		bad = 1;
	}
	n = changes_after(rb, &f);
	if (n != 0) {
		printf("     same packet again: %d events, want 0\n", n);
		bad = 1;
	}
	p.min_tx = htonl(20000);
	build_v4(&f, 255, BFD_PORT_1HOP, &p, 0);
	n = changes_after(rb, &f);
	if (n != 1) {
		printf("     new Desired Min TX: %d events, want 1\n", n);
		bad = 1;
	}

	/* Our Poll, then the peer's Final. */
	if (!bpf_map_lookup_elem(cfg_fd, &k, &cfg)) {
		cfg.poll = 1;
		cfg.poll_seq = 9;
		cfg_put(cfg_fd, &k, &cfg);
	}
	p.flags |= BFD_F_FINAL;
	build_v4(&f, 255, BFD_PORT_1HOP, &p, 0);
	n = changes_after(rb, &f);
	if (n != 1) {
		printf("     the peer's Final: %d events, want 1\n", n);
		bad = 1;
	}
	n = changes_after(rb, &f);
	if (n != 0) {
		printf("     Final again: %d events, want 0\n", n);
		bad = 1;
	}

	/* Two changes inside one window: one announcement, then the pending one
	 * with the next packet after it.
	 */
	p.flags &= ~BFD_F_FINAL;
	ring_buffer__consume(rb);
	usleep(2000);
	changes_seen = 0;
	p.min_tx = htonl(30000);
	build_v4(&f, 255, BFD_PORT_1HOP, &p, 0);
	run_frame(&f, NULL, NULL);
	p.min_tx = htonl(40000);
	build_v4(&f, 255, BFD_PORT_1HOP, &p, 0);
	run_frame(&f, NULL, NULL);
	ring_buffer__consume(rb);
	if (changes_seen != 1) {
		printf("     two changes in one window: %d events, want 1\n", changes_seen);
		bad = 1;
	}
	n = changes_after(rb, &f);
	if (n != 1) {
		printf("     the pending change after the window: %d events, want 1\n", n);
		bad = 1;
	}
	ring_buffer__free(rb);
	map_reset();
	if (bad) {
		printf("FAIL %-40s\n", "change-events");
		fails++;
	} else {
		printf("ok   %-40s first, changed, Final, throttled; repeats silent\n",
		       "change-events");
	}
}
