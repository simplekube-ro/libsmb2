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
 * External (application-supplied) transport backend.
 *
 * This backend implements struct smb2_transport_ops by delegating to the
 * application's struct smb2_external_transport callbacks (connect/send/recv/
 * close) carried in smb2->ext. Unlike the TCP backend it owns no file
 * descriptor: get_fd returns SMB2_INVALID_SOCKET, get_fds returns NULL, and
 * close never calls close() on a real socket; the application owns the
 * underlying transport handle behind ext.userdata.
 *
 * The application callbacks are untrusted: every entry point guards the
 * callback it invokes against NULL, and the byte counts returned by send/recv
 * are bounds-checked before they are fed into the SMB engine's I/O accounting.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#ifdef HAVE_SYS_POLL_H
#include <sys/poll.h>
#endif

#ifdef HAVE_POLL_H
#include <poll.h>
#endif

#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif

#ifdef HAVE_STRING_H
#include <string.h>
#endif

#ifdef HAVE_SYS_UIO_H
#include <sys/uio.h>
#endif

#ifdef HAVE_SYS__IOVEC_H
#include <sys/_iovec.h>
#endif

#ifdef HAVE_STDINT_H
#include <stdint.h>
#endif

#include <errno.h>
#include <limits.h>

#include "compat.h"

#include "slist.h"
#include "smb2.h"
#include "libsmb2.h"
#include "libsmb2-private.h"
#include "smb2-transport.h"

/*
 * Establish the transport via the application connect callback. The server
 * string is parsed into host + integer port using the same [ipv6]:port /
 * host:port / default-445 rules as the TCP backend, but no name resolution is
 * performed: the host string and port are handed verbatim to the application.
 * On success the connection is treated as immediately established, so the
 * connect callback is fired synchronously to start NEGOTIATE (the external
 * analogue of the moment tcp_service fires connect_cb once the socket
 * connects).
 */
static int
ext_connect(struct smb2_context *smb2, const char *server,
            smb2_command_cb cb, void *cb_data)
{
        char *addr, *host, *portstr;
        int port = 445;
        int ret;

        if (smb2->ext.connect == NULL) {
                smb2_set_error(smb2, "No external transport connect callback "
                               "registered.");
                return -EINVAL;
        }

        addr = strdup(server);
        if (addr == NULL) {
                smb2_set_error(smb2, "Out-of-memory: "
                               "Failed to strdup server address.");
                return -ENOMEM;
        }
        host = addr;
        portstr = host;

        /* ipv6 in [...] form ? */
        if (host[0] == '[') {
                char *str;

                host++;
                str = strchr(host, ']');
                if (str == NULL) {
                        free(addr);
                        smb2_set_error(smb2, "Invalid address:%s  "
                                "Missing ']' in IPv6 address", server);
                        return -EINVAL;
                }
                *str = 0;
                portstr = str + 1;
        }

        portstr = strchr(portstr, ':');
        if (portstr != NULL) {
                *portstr++ = 0;
                port = (int)strtol(portstr, NULL, 10);
        }

        ret = smb2->ext.connect(smb2->ext.userdata, host, port);
        free(addr);
        if (ret < 0) {
                smb2_set_error(smb2, "External transport connect failed (%d).",
                               ret);
                return ret;
        }

        /* The transport is up. Mark the context connected (the external
         * backend owns no fd, so this flag is the connectedness predicate used
         * by smb2_transport_is_connected). */
        smb2->ext_connected = 1;

        /* Fire the connect callback synchronously to kick off the NEGOTIATE
         * exchange, mirroring tcp_service's behaviour once a socket finishes
         * connecting. */
        smb2->connect_cb   = cb;
        smb2->connect_data = cb_data;
        if (smb2->connect_cb) {
                smb2->connect_cb(smb2, 0, NULL, smb2->connect_data);
                smb2->connect_cb = NULL;
        }

        return 0;
}

/*
 * Drive the read/write state machine for the external transport. The fd
 * argument is ignored (there is no pollable descriptor); readiness is supplied
 * by the event loop as poll revents derived from ext_which_events. There is no
 * Happy-Eyeballs / connect-race handling here because connect completes
 * synchronously in ext_connect.
 */
static int
ext_service(struct smb2_context *smb2, t_socket fd, int revents)
{
        int ret = 0;

        (void)fd;

        if (revents & POLLIN) {
                if (smb2_read_from_ext(smb2) != 0) {
                        ret = -1;
                        goto out;
                }
        }

        if (revents & POLLOUT && smb2->outqueue != NULL) {
                if (smb2_write_to_socket(smb2) != 0) {
                        ret = -1;
                        goto out;
                }
        }

 out:
        if (smb2->timeout) {
                smb2_timeout_pdus(smb2);
        }
        return ret;
}

/*
 * Send the scatter-gather vector to the wire via the application send
 * callback. This must behave like writev() for the engine's accounting: walk
 * the vectors, send each non-empty one, accumulate a byte total, and stop on a
 * short write so the engine retries the remainder. The callback is untrusted,
 * so the requested length is clamped to INT_MAX and a return larger than the
 * requested length is rejected. errno is left as the callback set it on error
 * (the caller inspects it for EAGAIN/EWOULDBLOCK).
 */
static ssize_t
ext_queue_write(struct smb2_context *smb2, const struct iovec *iov, int niov)
{
        ssize_t total = 0;
        int i;

        if (smb2->ext.send == NULL) {
                errno = EINVAL;
                return -1;
        }

        for (i = 0; i < niov; i++) {
                size_t len = iov[i].iov_len;
                int ret;

                if (len == 0) {
                        continue;
                }
                if (len > (size_t)INT_MAX) {
                        len = (size_t)INT_MAX;
                }

                ret = smb2->ext.send(smb2->ext.userdata,
                                     (const uint8_t *)iov[i].iov_base, len);
                if (ret < 0) {
                        /* Hand back what we already sent so the engine retries
                         * the remainder; otherwise preserve the callback's
                         * errno for the EAGAIN/EWOULDBLOCK check. */
                        if (total > 0) {
                                return total;
                        }
                        return -1;
                }
                if ((size_t)ret > len) {
                        /* A buggy/hostile callback must not advance
                         * pdu->out.num_done past what we handed it. */
                        smb2_set_error(smb2, "external send returned more bytes "
                                       "(%d) than requested (%d)", ret,
                                       (int)len);
                        if (total > 0) {
                                return total;
                        }
                        errno = EIO;
                        return -1;
                }
                total += ret;
                if ((size_t)ret < len) {
                        /* Short write: stop so the engine retries the rest. */
                        break;
                }
        }

        return total;
}

/*
 * Tear down the external transport via the application close callback. A NULL
 * close callback is a no-op success. No real file descriptor is ever closed;
 * the fd field is reset to the invalid sentinel for hygiene only.
 */
static int
ext_close(struct smb2_context *smb2)
{
        if (smb2->ext.close) {
                smb2->ext.close(smb2->ext.userdata);
        }
        smb2->ext_connected = 0;
        smb2->fd = SMB2_INVALID_SOCKET;
        return 0;
}

/*
 * Report the poll event mask for buffered-I/O readiness. There is no real fd,
 * so we always want POLLIN, and add POLLOUT when there is queued output we
 * have the credits to send (mirroring tcp_which_events minus the connect-race
 * branch).
 */
static int
ext_which_events(struct smb2_context *smb2)
{
        int events = POLLIN;

        if (smb2->outqueue != NULL &&
            smb2_get_credit_charge(smb2, smb2->outqueue) <= smb2->credits) {
                events |= POLLOUT;
        }

        return events;
}

/*
 * The external backend owns no descriptor, so there is nothing pollable to
 * return. Event loops express readiness through ext_which_events instead.
 */
static t_socket
ext_get_fd(struct smb2_context *smb2)
{
        (void)smb2;
        return SMB2_INVALID_SOCKET;
}

static const t_socket *
ext_get_fds(struct smb2_context *smb2, size_t *fd_count, int *timeout)
{
        (void)smb2;
        *fd_count = 0;
        *timeout = -1;
        return NULL;
}

const struct smb2_transport_ops smb2_external_transport_ops = {
        ext_connect,
        ext_service,
        ext_queue_write,
        ext_close,
        ext_which_events,
        ext_get_fd,
        ext_get_fds,
};
