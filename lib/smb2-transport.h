/* -*-  mode:c; tab-width:8; c-basic-offset:8; indent-tabs-mode:nil;  -*- */
#ifndef _LIBSMB2_TRANSPORT_H_
#define _LIBSMB2_TRANSPORT_H_

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

#ifdef __cplusplus
extern "C" {
#endif

struct smb2_context;

/*
 * Internal transport operations table.
 *
 * This abstracts the connect / service / send / poll / close operations so
 * that the SMB engine does not have to assume it owns a POSIX TCP socket.
 * The default backend is the TCP backend (smb2_tcp_transport_ops) which is
 * registered on every context in smb2_init_context() via
 *     smb2->transport = &smb2_tcp_transport_ops;
 * Stage 1 exposes no public API to change this binding, so for every existing
 * caller each smb2->transport->op() call resolves to exactly the tcp_* function
 * that used to be the inline implementation. The public/engine entry points are
 * thin dispatchers that forward their arguments unchanged; each one guards
 * against a NULL transport or NULL op and returns the documented error value
 * below (this can only happen for a future external backend, never for TCP), so
 * the TCP happy path is byte-for-byte the prior control flow.
 *
 * The seven operations (entry point -> TCP impl, in lib/socket.c unless noted):
 *
 *   connect       smb2_connect_async  -> tcp_connect
 *                 Begin async connection establishment to `server`; invokes `cb`
 *                 with `cb_data` on completion. Returns 0 on a successfully
 *                 started connect, a negative errno otherwise. Dispatcher
 *                 returns -EINVAL when no connect op is registered.
 *
 *   service       smb2_service_fd     -> tcp_service
 *                 Drive the read/write state machine for `fd` given poll
 *                 `revents`; for TCP this also advances the multi-fd
 *                 Happy-Eyeballs connect race. smb2_service() is a convenience
 *                 wrapper that picks the right fd and calls smb2_service_fd().
 *                 Returns 0 on success, -1 on error (also returned by the
 *                 dispatcher when no service op is registered).
 *
 *   queue_write   smb2_write_to_socket -> tcp_queue_write
 *                 Write the scatter-gather vector `iov`/`niov` to the wire. The
 *                 TCP impl is a bare writev() that must not clobber errno, which
 *                 the caller inspects for EAGAIN/EWOULDBLOCK. Returns the byte
 *                 count or -1 (with errno set) like writev().
 *
 *   close         smb2_destroy_context (init.c), smb2_disconnect/free paths
 *                 (libsmb2.c) -> tcp_close
 *                 Tear down the connection, handling both an established fd and
 *                 the mid-Happy-Eyeballs case. Returns 0.
 *
 *   which_events  smb2_which_events   -> tcp_which_events
 *                 Return the poll event mask (POLLIN/POLLOUT) the caller should
 *                 wait on. Dispatcher returns 0 when no op is registered.
 *
 *   get_fd        smb2_get_fd         -> tcp_get_fd
 *                 Return the single fd to poll (or the first connecting fd), or
 *                 -1 if none / no op is registered.
 *
 *   get_fds       smb2_get_fds        -> tcp_get_fds
 *                 Return the array of fds to poll (the whole Happy-Eyeballs
 *                 connecting set while racing, then the single fd) and the
 *                 desired poll `timeout`. Dispatcher returns NULL with
 *                 *fd_count = 0 when no op is registered. Event loops that need
 *                 parallel connect MUST use this rather than get_fd.
 *
 * Note: t_socket is provided by compat.h and smb2_command_cb by
 * smb2/libsmb2.h; both must be included before this header.
 */
struct smb2_transport_ops {
        int      (*connect)(struct smb2_context *smb2, const char *server,
                            smb2_command_cb cb, void *cb_data);
        int      (*service)(struct smb2_context *smb2, t_socket fd,
                            int revents);
        ssize_t  (*queue_write)(struct smb2_context *smb2,
                                const struct iovec *iov, int niov);
        int      (*close)(struct smb2_context *smb2);
        int      (*which_events)(struct smb2_context *smb2);
        t_socket (*get_fd)(struct smb2_context *smb2);
        const t_socket *(*get_fds)(struct smb2_context *smb2,
                                   size_t *fd_count, int *timeout);
};

/* Default TCP transport backend. */
extern const struct smb2_transport_ops smb2_tcp_transport_ops;

#ifdef __cplusplus
}
#endif

#endif /* !_LIBSMB2_TRANSPORT_H_ */
