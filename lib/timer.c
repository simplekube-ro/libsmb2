/* -*-  mode:c; tab-width:8; c-basic-offset:8; indent-tabs-mode:nil;  -*- */
/*
   Copyright (C) 2026 by Cristian Calin <cristian.calin@simplekube.ro>

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU Lesser General Public License as published by
   the Free Software Foundation; either version 2.1 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public License
   along with this program; if not, see <http://www.gnu.org/licenses/>.
*/

/*
 * Transport-agnostic timer API.
 *
 * smb2_get_timeout()/smb2_service_timeout() let an event loop bound its wait
 * and run timer-driven work. They operate on the engine's queues and the
 * cached smb2->next_timeout deadline, so they work regardless of the selected
 * transport backend. For TCP they map onto the existing per-request timeout
 * machinery (smb2_set_timeout()/smb2_timeout_pdus()); for an external/QUIC
 * transport they additionally honour a backend-published next_timeout.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <errno.h>
#include <limits.h>

#ifdef HAVE_SYS_TIME_H
#include <sys/time.h>
#endif

#ifdef HAVE_TIME_H
#include <time.h>
#endif

#ifdef HAVE_SYS_UIO_H
#include <sys/uio.h>
#endif

#ifdef HAVE_SYS__IOVEC_H
#include <sys/_iovec.h>
#endif

#include "compat.h"

#include "slist.h"
#include "smb2.h"
#include "libsmb2.h"
#include "libsmb2-private.h"
#include "smb2-transport.h"     /* struct smb2_transport_ops (timer dispatch) */

/*
 * Scan the engine queues and the backend-published deadline for the earliest
 * absolute deadline pending. Returns 1 and stores it in *deadline, or 0 when
 * no timer is pending. Shared by smb2_get_timeout() (the struct timeval
 * accessor) and smb2_next_timeout_ms() (the millisecond accessor used to bound
 * an event loop's poll wait).
 */
static int
smb2_earliest_deadline(struct smb2_context *smb2, time_t *deadline)
{
        struct smb2_pdu *pdu;
        int have = 0;

        for (pdu = smb2->outqueue; pdu; pdu = pdu->next) {
                if (pdu->timeout && (!have || pdu->timeout < *deadline)) {
                        *deadline = pdu->timeout;
                        have = 1;
                }
        }
        for (pdu = smb2->waitqueue; pdu; pdu = pdu->next) {
                if (pdu->timeout && (!have || pdu->timeout < *deadline)) {
                        *deadline = pdu->timeout;
                        have = 1;
                }
        }

        /* A transport backend may publish an earlier deadline of its own. */
        if (smb2->next_timeout && (!have || smb2->next_timeout < *deadline)) {
                *deadline = smb2->next_timeout;
                have = 1;
        }

        return have;
}

int
smb2_get_timeout(struct smb2_context *smb2, struct timeval *tv)
{
        time_t now, deadline = 0;

        if (smb2 == NULL || tv == NULL) {
                return -EINVAL;
        }

        if (!smb2_earliest_deadline(smb2, &deadline)) {
                return 0;               /* no timer pending */
        }

        now = time(NULL);
        tv->tv_usec = 0;
        tv->tv_sec  = (deadline > now) ? (deadline - now) : 0;
        return 1;
}

/*
 * Milliseconds until the next pending deadline, suitable as a poll(2) timeout:
 *   -1      no deadline pending (wait indefinitely)
 *    0      a deadline is already due
 *   >0      milliseconds remaining (clamped to INT_MAX)
 * Used by smb2_get_fds() to narrow the poll timeout it returns to the caller.
 */
int
smb2_next_timeout_ms(struct smb2_context *smb2)
{
        time_t now, deadline = 0, secs;

        if (smb2 == NULL) {
                return -1;
        }

        if (!smb2_earliest_deadline(smb2, &deadline)) {
                return -1;
        }

        now = time(NULL);
        if (deadline <= now) {
                return 0;
        }
        secs = deadline - now;
        if (secs > (time_t)(INT_MAX / 1000)) {
                return INT_MAX;
        }
        return (int)(secs * 1000);
}

int
smb2_service_timeout(struct smb2_context *smb2)
{
        if (smb2 == NULL) {
                return -EINVAL;
        }
        if (smb2->timeout) {
                smb2_timeout_pdus(smb2); /* per-pdu deadline check is internal */
        }
        /* Advance backend timer-driven work (handshake/idle/loss-recovery for
         * an external backend). TCP binds this to NULL: a clean no-op. */
        if (smb2->transport && smb2->transport->timer) {
                smb2->transport->timer(smb2);
        }
        return 0;
}
