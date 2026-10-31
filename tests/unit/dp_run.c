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
#include "dp/t_scale.c"

int main(void)
{
	if (sess_table_init(BFD_MAX_SESSIONS) || !rig_up()) {
		printf("rig setup failed\n");
		return 1;
	}

	case_capabilities();
	case_whole();
	case_auth_rollover();
	case_auth_short();
	case_auth_unsupported_type();
	case_auth_rfc_flag("auth-rfc-flag-kept", BFDDP_AUTH_KEY_RFC_SHA1, 20, 1,
			   BFD_AUTH_F_RFC_SHA1);
	case_auth_rfc_flag("auth-no-flag-is-hmac", 0, 21, 1, 0);
	case_auth_rfc_flag("auth-rfc-key-over-20-dropped", BFDDP_AUTH_KEY_RFC_SHA1, 21, 0, 0);
	case_auth_rfc_flag("auth-unknown-flag-dropped", 0x02, 8, 0, 0);
	case_torn();
	case_batched();

	case_fresh();
	case_fresh_v6();
	case_update_keeps_disc();
	case_add_without_auth();
	case_add_without_interface();
	case_mirror_cache_tracks_key();
	case_repeated_add_during_poll();
	case_address_move();
	case_flags();
	case_notify_coalesce();
	case_reconnect_resyncs_state();
	case_second_connection_waits(1);
	case_second_connection_waits(0);
	case_send_failure_defers_teardown();
	case_counters_reply_fits_during_storm();
	case_adopted_disc_not_reissued();
	case_local_resolve();
	case_local_resolve_v6();
	case_local_resolve_mhop();
	case_index_matches_scan();
	case_table_fills();

	/* Below the header, and above the buffer. */
	case_bad_length(sizeof(struct bfddp_message_header) - 1, "bad-length-under-header");
	case_bad_length(0, "bad-length-zero");
	case_bad_length(65535, "bad-length-over-buffer");

	rig_down();
	printf("\n%d failure(s)\n", fails);
	return fails ? 1 : 0;
}
