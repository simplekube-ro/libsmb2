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
 * registered on every context in smb2_init_context().
 *
 * Note: t_socket is provided by compat.h and smb2_command_cb by
 * smb2/libsmb2.h; both must be included before this header.
 */
struct smb2_transport_ops {
        int      (*connect)(struct smb2_context *smb2, const char *server,
                            smb2_command_cb cb, void *cb_data);
        int      (*service)(struct smb2_context *smb2, t_socket fd,
                            int revents);
        int      (*queue_write)(struct smb2_context *smb2,
                                const uint8_t *buf, size_t len);
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
