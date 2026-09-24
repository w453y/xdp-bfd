// SPDX-License-Identifier: GPL-2.0
/* Part of xdp_run.c. */

/* ktx_mirror's writes, from another CPU: two configs of the session under test
 * and two of a neighbour, whose elements a replacing update would recycle.
 */
struct race {
	volatile int stop;
	int cpu;
	long writes;
};

static void race_cfg(struct tx_cfg *c, __u32 my, __u32 your, __u8 mult, __u32 tx)
{
	memset(c, 0, sizeof(*c));
	c->enable = 1;
	c->my_disc = my;
	c->your_disc = your;
	c->min_tx_us = tx;
	c->min_rx_us = tx;
	c->state = ST_UP;
	c->mult = mult;
	c->min_ttl = 255;
}

static void *race_writer(void *arg)
{
	struct race *r = arg;
	struct session_key ka = key_v4("10.0.0.2", "10.0.0.1");
	struct session_key kb = key_v4("10.0.0.3", "10.0.0.1");
	struct tx_cfg a1, a2, b1, b2;
	cpu_set_t set;

	CPU_ZERO(&set);
	CPU_SET(r->cpu, &set);
	pthread_setaffinity_np(pthread_self(), sizeof(set), &set);

	race_cfg(&a1, 0x22222222, 0x11111111, 3, 10000);
	race_cfg(&a2, 0x22222222, 0x11111111, 4, 20000);
	race_cfg(&b1, 0x33333333, 0x44444444, 5, 30000);
	race_cfg(&b2, 0x33333333, 0x44444444, 6, 40000);
	while (!r->stop) {
		cfg_put(cfg_fd, &ka, &a1);
		cfg_put(cfg_fd, &kb, &b1);
		cfg_put(cfg_fd, &ka, &a2);
		cfg_put(cfg_fd, &kb, &b2);
		r->writes += 4;
	}
	return NULL;
}

/* Every reply is one of the session's two configs, whole: never the
 * neighbour's, never a mix, never dropped.
 */
static void case_cfg_update_race(void)
{
	struct session_key kb = key_v4("10.0.0.3", "10.0.0.1");
	struct bfd_ctrl_pkt p = ctrl_up();
	struct race r = { 0 };
	long drops = 0, foreign = 0, torn = 0;
	const long runs = 500000;
	cpu_set_t set;
	pthread_t t;
	struct frame f;
	int me = sched_getcpu();

	if (me < 0 || libbpf_num_possible_cpus() < 2) {
		printf("skip %-40s needs two CPUs\n", "cfg-update-race");
		return;
	}
	CPU_ZERO(&set);
	CPU_SET(me, &set);
	sched_setaffinity(0, sizeof(set), &set);
	r.cpu = me ? 0 : 1;

	map_reset();
	arm_session();
	build_v4(&f, 255, BFD_PORT_1HOP, &p, 0);
	pthread_create(&t, NULL, race_writer, &r);

	for (long i = 0; i < runs; i++) {
		unsigned char out[FRAME_MAX];
		unsigned int out_len = 0;

		if (run_frame(&f, out, &out_len) != XDP_TX) {
			drops++;
			continue;
		}

		const struct bfd_ctrl_pkt *ob = (const void *)(out + sizeof(struct ethhdr) +
							       sizeof(struct iphdr) +
							       sizeof(struct udphdr));
		__u32 tx = ntohl(ob->min_tx);

		if (ntohl(ob->my_disc) != 0x22222222)
			foreign++;
		else if (!(ob->detect_mult == 3 && tx == 10000) &&
			 !(ob->detect_mult == 4 && tx == 20000))
			torn++;
	}
	r.stop = 1;
	pthread_join(t, NULL);
	CPU_ZERO(&set);
	for (int i = 0; i < libbpf_num_possible_cpus(); i++)
		CPU_SET(i, &set);
	sched_setaffinity(0, sizeof(set), &set);

	if (drops || foreign || torn) {
		printf("FAIL %-40s %ld dropped, %ld foreign, %ld torn in %ld runs, %ld writes\n",
		       "cfg-update-race", drops, foreign, torn, runs, r.writes);
		fails++;
	} else {
		printf("ok   %-40s %ld runs, %ld writes\n", "cfg-update-race", runs, r.writes);
	}
	bpf_map_delete_elem(cfg_fd, &kb);
	map_reset();
}
