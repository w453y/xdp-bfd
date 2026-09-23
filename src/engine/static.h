// SPDX-License-Identifier: GPL-2.0
/* static.h - one session from the command line, without bfdd. */
#ifndef BFD_ENGINE_STATIC_H
#define BFD_ENGINE_STATIC_H

#include "opts.h"

/* Create the session o->local -> o->peer. 0 on success. */
int static_session_add(const struct opts *o);

#endif /* BFD_ENGINE_STATIC_H */
