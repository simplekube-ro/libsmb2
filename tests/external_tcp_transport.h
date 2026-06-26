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
 * Test-owned TCP transport fixture for libsmb2's external-transport backend.
 *
 * This helper implements the four struct smb2_external_transport callbacks
 * (connect/send/recv/close) on top of a plain TCP socket that the TEST owns:
 * the socket is created here by connect(2) and torn down here by close(2).
 * libsmb2 itself never creates or owns the descriptor; it only ever sees the
 * opaque byte stream through the callbacks. This proves the SMB engine runs
 * with zero internal fd ownership (RandomPlayer#344 acceptance criterion #2).
 */

#ifndef _EXTERNAL_TCP_TRANSPORT_H_
#define _EXTERNAL_TCP_TRANSPORT_H_

#include "smb2.h"
#include "libsmb2.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Opaque-ish state for the test-owned socket. The single descriptor lives
 * here, owned by the test, and must outlive the smb2_context it backs (it is
 * referenced through ext.userdata). Initialize fd to -1 before use.
 */
struct ext_tcp {
        int fd;
};

/*
 * Populate an smb2_external_transport with the four TCP callbacks, wiring
 * userdata to the supplied test-owned state. After this call, hand ext to
 * smb2_set_transport(smb2, SMB2_TRANSPORT_AUTO, &ext).
 */
void ext_tcp_fill(struct smb2_external_transport *ext, struct ext_tcp *t);

#ifdef __cplusplus
}
#endif

#endif /* !_EXTERNAL_TCP_TRANSPORT_H_ */
