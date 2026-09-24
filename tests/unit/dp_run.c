// SPDX-License-Identifier: GPL-2.0
/* dp_run.c - the bfddp parser over a real Unix socket, through the engine's
 * accept path; only ktx is stubbed.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h>
#include <endian.h>
#include <stdint.h>
#include <unistd.h>
#include <errno.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/un.h>

#include "session.h"
#include "dplane.h"
#include "fsm.h"
#include "util.h"
#include "bfddp.h"

#include "ktx_stubs.h"
#include "report.h"

#include "dp/harness.c"
#include "dp/t_frame.c"
#include "dp/t_add.c"
#include "dp/t_auth.c"
#include "dp/t_notify.c"
#include "dp/t_resolve.c"
#include "dp/t_resync.c"
#include "dp/t_index.c"

int main(void)
{
	if (sess_table_init(BFD_MAX_SESSIONS) || !rig_up()) {
		printf("rig setup failed\n");
		return 1;
	}

	case_whole();
	case_auth_rollover();
	case_auth_short();
	case_auth_unsupported_type();
	case_torn();
	case_batched();

	case_fresh();
	case_fresh_v6();
	case_update_keeps_disc();
	case_add_without_auth();
	case_mirror_cache_tracks_key();
	case_repeated_add_during_poll();
	case_address_move();
	case_flags();
	case_notify_coalesce();
	case_reconnect_resyncs_state();
	case_counters_reply_fits_during_storm();
	case_adopted_disc_not_reissued();
	case_local_resolve();
	case_local_resolve_v6();
	case_local_resolve_mhop();
	case_index_matches_scan();

	/* Below the header, and above the buffer. */
	case_bad_length(sizeof(struct bfddp_message_header) - 1, "bad-length-under-header");
	case_bad_length(0, "bad-length-zero");
	case_bad_length(65535, "bad-length-over-buffer");

	rig_down();
	printf("\n%d failure(s)\n", fails);
	return fails ? 1 : 0;
}
