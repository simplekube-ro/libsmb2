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
 * Pure in-memory loopback transport test (NO sockets, NO server).
 *
 * This drives a real libsmb2 SMB exchange entirely through the four external-
 * transport callbacks, backed by in-memory byte queues and a scripted server
 * responder (mock_transport.c / recorded_exchange.h). It proves the SMB engine
 * needs no internally-owned socket (RandomPlayer#344 acceptance criterion #2)
 * and that it parses a crafted server response -- deterministically, with no
 * network -- so it is safe to run unconditionally in CI.
 *
 * Determinism strategy (why this is honest, not a no-op):
 *   - Dialect is pinned to SMB 2.0.2 (smb2_set_version): no negotiate contexts,
 *     no SMB3.1.1 pre-auth integrity salts.
 *   - Signing is disabled (smb2_set_security_mode(0)): the engine does not
 *     verify response signatures, so the unsigned scripted reply is accepted.
 *   - The responder keys only on parsed Command + MessageId, never on the
 *     client's per-run-random bytes (client GUID / NTLM challenge / timestamps).
 *
 * What is genuinely exercised here: the NEGOTIATE round-trip. The engine emits
 * a NEGOTIATE request (app->server bytes), the mock parses it and stages a
 * crafted NEGOTIATE reply (server->app bytes), and the engine PARSES that reply
 * and advances its state machine far enough to emit a SESSION_SETUP request
 * (carrying an NTLMSSP type-1 token) -- which it only does on a valid negotiate
 * reply. That session-setup emission is the parse proof. Completing the
 * authenticated SESSION_SETUP / TREE_CONNECT drive-through (NTLM/SPNEGO) belongs
 * to the dependent live/full-exchange work (#15); we deliberately stop the
 * bounded pump loop once the engine has emitted SESSION_SETUP, so this test
 * never blocks and never asserts success it did not observe.
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "smb2.h"
#include "libsmb2.h"
#include "libsmb2-raw.h"

#include "mock_transport.h"

/*
 * The public header exposes t_socket but not the invalid-socket sentinel (that
 * lives in the internal compat.h). Mirror the documented contract on the public
 * surface: smb2_get_fd() returns the platform's invalid socket for a transport
 * that owns no descriptor. On POSIX t_socket is int and the sentinel is -1.
 */
#if defined(_WIN32) || defined(_XBOX) || defined(__MINGW32__)
#define EXT_INVALID_SOCKET INVALID_SOCKET
#else
#define EXT_INVALID_SOCKET ((t_socket)-1)
#endif

/* Upper bound on service iterations: the deterministic handshake reaches the
 * SESSION_SETUP emission in a handful of iterations; this only guards against a
 * regression that would otherwise spin. */
#define MOCK_MAX_ITERS 256

struct done_state {
        int finished;
        int status;
};

static void
connect_done_cb(struct smb2_context *smb2, int status,
                void *command_data, void *private_data)
{
        struct done_state *d = private_data;

        (void)smb2;
        (void)command_data;
        d->finished = 1;
        d->status = status;
}

int main(void)
{
        struct smb2_context *smb2;
        struct mock_transport m;
        struct smb2_external_transport ext;
        struct done_state done;
        const t_socket *fds;
        size_t fd_count = (size_t)-1;
        int fds_timeout = 0;
        int i;
        int rc = 1;

        if (mock_transport_init(&m) < 0) {
                fprintf(stderr, "mock_transport_init failed\n");
                return 1;
        }

        smb2 = smb2_init_context();
        if (smb2 == NULL) {
                fprintf(stderr, "Failed to init context\n");
                mock_transport_destroy(&m);
                return 1;
        }

        /* Install the in-memory transport BEFORE connecting. ext is copied by
         * value into the context; the mock state m backs ext.userdata and must
         * outlive the context. */
        memset(&ext, 0, sizeof(ext));
        mock_transport_fill(&ext, &m);
        if (smb2_set_transport(smb2, SMB2_TRANSPORT_AUTO, &ext) < 0) {
                fprintf(stderr, "smb2_set_transport failed: %s\n",
                        smb2_get_error(smb2));
                goto out;
        }

        /* Pin the deterministic path: dialect 2.0.2, signing off. */
        smb2_set_security_mode(smb2, 0);
        smb2_set_version(smb2, SMB2_VERSION_0202);
        smb2_set_user(smb2, "mockuser");
        smb2_set_password(smb2, "mockpass");

        memset(&done, 0, sizeof(done));
        if (smb2_connect_share_async(smb2, "mockhost", "share", "mockuser",
                                     connect_done_cb, &done) < 0) {
                fprintf(stderr, "smb2_connect_share_async failed: %s\n",
                        smb2_get_error(smb2));
                goto out;
        }

        /* The connect callback fired synchronously through the external backend
         * and queued the NEGOTIATE request. Drive the read/write state machine
         * by hand (no sockets, no poll) until the engine has consumed our
         * crafted NEGOTIATE reply and emitted SESSION_SETUP. */
        for (i = 0; i < MOCK_MAX_ITERS; i++) {
                int events = smb2_which_events(smb2);

                if (smb2_service(smb2, events) < 0) {
                        fprintf(stderr, "smb2_service failed: %s\n",
                                smb2_get_error(smb2));
                        goto out;
                }
                if (done.finished || m.saw_session_setup) {
                        break;
                }
        }

        /* --- Assertion 1: the engine owns NO pollable descriptor. --- */
        assert(smb2_get_fd(smb2) == EXT_INVALID_SOCKET);
        fds = smb2_get_fds(smb2, &fd_count, &fds_timeout);
        assert(fds == NULL);
        assert(fd_count == 0);

        /* --- Assertion 2: zero sockets were ever created. --- */
        assert(m.socket_calls == 0);
        assert(m.connected == 1);

        /* --- Assertion 3: real bidirectional byte movement occurred. --- */
        assert(m.bytes_sent > 0);
        assert(m.bytes_recvd > 0);

        /* --- Assertion 4: the engine parsed our crafted NEGOTIATE reply. ---
         * It only emits a SESSION_SETUP request after successfully processing
         * the negotiate reply, so observing that request is the parse proof. */
        assert(m.saw_negotiate == 1);
        assert(m.sent_negotiate_rep == 1);
        assert(m.saw_session_setup == 1);

        printf("in-memory mock transport: OK\n");
        printf("  sockets created            : %lu\n", m.socket_calls);
        printf("  app->server bytes (sent)   : %zu\n", m.bytes_sent);
        printf("  server->app bytes (recvd)  : %zu\n", m.bytes_recvd);
        printf("  request PDUs parsed by mock: %lu\n", m.pdus_seen);
        printf("  smb2_get_fd()              : invalid (no socket)\n");
        printf("  reached                    : NEGOTIATE replied, "
               "engine emitted SESSION_SETUP\n");

        rc = 0;

 out:
        smb2_destroy_context(smb2);
        mock_transport_destroy(&m);
        return rc;
}
