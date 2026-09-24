// SPDX-License-Identifier: GPL-2.0
/* ktx_pin.c - --pin: the state maps and XDP links outlive the engine, so a
 * restarted one takes over the running program and its sessions.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <errno.h>
#include <dirent.h>
#include <sys/stat.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#include "bfd_shared.h"
#include "log.h"
#include "ktx.h"

const char *ktx_pin_dir; /* --pin, or NULL */
int ktx_reused;		 /* the state maps came from a pin */
static char pin_sub[512];

/* The state a restart must keep. Scratch, the rings and the sweep timer's map
 * start fresh with the new program, which arms its own timer.
 */
static const char *const pinned[] = {
	"bfd_sessions", "tx_config",  "auth_seq", "echo_peers", "echo_disc",
	"our_discs",	"prog_flags", "tunables", "heartbeat",	"bfd_stats",
};

/* A build whose maps differ must not inherit them: the sizes, and
 * BFD_PIN_ABI for a change that keeps them.
 */
static uint32_t pin_abi(void)
{
	const uint32_t v[] = {
		sizeof(struct session_key),
		sizeof(struct session_state),
		sizeof(struct tx_cfg),
		sizeof(struct echo_peer),
		BFD_MAX_SESSIONS,
		BFD_STAT_MAX,
		BFD_TUNE_MAX,
		BFD_PIN_ABI,
	};
	const uint8_t *b = (const uint8_t *)v;
	uint32_t h = 2166136261u;

	for (size_t i = 0; i < sizeof(v); i++)
		h = (h ^ b[i]) * 16777619u;
	return h;
}

static void rm_dir(const char *dir)
{
	DIR *d = opendir(dir);
	struct dirent *e;
	char p[768];

	if (!d)
		return;
	while ((e = readdir(d))) {
		if (e->d_name[0] == '.')
			continue;
		snprintf(p, sizeof(p), "%s/%s", dir, e->d_name);
		unlink(p);
	}
	closedir(d);
	rmdir(dir);
}

/* Before load. Drops what another build pinned, so its program detaches. */
int ktx_pin_prepare(struct bpf_object *o)
{
	char p[768];
	DIR *d;
	struct dirent *e;

	if (!ktx_pin_dir)
		return 0;
	if (strlen(ktx_pin_dir) > 200) {
		log_err("--pin: %s is too long a path\n", ktx_pin_dir);
		return -1;
	}
	snprintf(pin_sub, sizeof(pin_sub), "%s/abi-%08x", ktx_pin_dir, pin_abi());
	if (mkdir(ktx_pin_dir, 0700) && errno != EEXIST) {
		log_err("--pin: cannot create %s: %s\n", ktx_pin_dir, strerror(errno));
		return -1;
	}
	d = opendir(ktx_pin_dir);
	while (d && (e = readdir(d))) {
		snprintf(p, sizeof(p), "%s/%s", ktx_pin_dir, e->d_name);
		if (strncmp(e->d_name, "abi-", 4) || !strcmp(p, pin_sub))
			continue;
		log_info("--pin: discarding %s, pinned by a build with other maps\n", p);
		rm_dir(p);
	}
	if (d)
		closedir(d);
	if (mkdir(pin_sub, 0700) && errno != EEXIST) {
		log_err("--pin: cannot create %s: %s\n", pin_sub, strerror(errno));
		return -1;
	}

	ktx_reused = 0;
	for (size_t i = 0; i < sizeof(pinned) / sizeof(pinned[0]); i++) {
		struct bpf_map *m = bpf_object__find_map_by_name(o, pinned[i]);

		if (!m)
			continue;
		snprintf(p, sizeof(p), "%s/%s", pin_sub, pinned[i]);
		if (!access(p, F_OK))
			ktx_reused = 1;
		if (bpf_map__set_pin_path(m, p))
			return -1;
	}
	return 0;
}

/* A load that could not reuse the pins starts over without them. */
void ktx_pin_discard(void)
{
	if (!ktx_pin_dir || !pin_sub[0])
		return;
	log_err("--pin: the pinned state did not load with this object; starting fresh\n");
	rm_dir(pin_sub);
	ktx_reused = 0;
}

/* The pinned link on ifindex, now running prog; -1 if there is none. */
int ktx_pin_take_link(int ifindex, int prog_fd)
{
	char p[768];
	int fd;

	if (!ktx_pin_dir)
		return -1;
	snprintf(p, sizeof(p), "%s/link-%d", pin_sub, ifindex);
	fd = bpf_obj_get(p);
	if (fd < 0)
		return -1;
	if (bpf_link_update(fd, prog_fd, NULL)) {
		log_err("--pin: cannot swap the program on %s: %s\n", p, strerror(errno));
		close(fd);
		unlink(p);
		return -1;
	}
	return fd;
}

void ktx_pin_link(int ifindex, int link_fd)
{
	char p[768];

	if (!ktx_pin_dir || link_fd < 0)
		return;
	snprintf(p, sizeof(p), "%s/link-%d", pin_sub, ifindex);
	if (bpf_obj_pin(link_fd, p))
		log_err("--pin: cannot pin %s: %s; a restart will not be seamless\n", p,
			strerror(errno));
}

/* An orderly stop: nothing outlives us. */
void ktx_unpin(void)
{
	if (!ktx_pin_dir)
		return;
	if (pin_sub[0])
		rm_dir(pin_sub);
}
