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
 * Pure in-memory loopback transport fixture for libsmb2's external-transport
 * backend.
 *
 * Unlike external_tcp_transport.c (which carries the SMB2 byte stream over a
 * real, test-owned TCP socket), this fixture implements the four
 * struct smb2_external_transport callbacks (connect/send/recv/close) over two
 * in-memory byte queues and a small scripted server responder. NO socket(2) is
 * ever created, by libsmb2 or by the fixture: the entire handshake is driven
 * deterministically through the callbacks with zero file descriptors and no
 * network, so it is safe to run unconditionally in CI.
 *
 * The app->server queue ("tx") collects the bytes libsmb2 emits; whenever a
 * complete direct-TCP framed PDU has accumulated, the responder parses it and
 * stages the matching server reply into the server->app queue ("rx"), which is
 * then drained back into the engine through the recv callback. This proves the
 * SMB engine runs with zero internal fd ownership (RandomPlayer#344 acceptance
 * criterion #2) and parses crafted server responses, independent of any live
 * server.
 */

#ifndef _MOCK_TRANSPORT_H_
#define _MOCK_TRANSPORT_H_

#include <stddef.h>
#include <stdint.h>

#include "smb2.h"
#include "libsmb2.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * A trivial growable byte buffer with a consumed-offset cursor. Producers
 * append at [len]; consumers read from [off]. Bytes before off have been
 * consumed and are never revisited.
 */
struct mock_buf {
        uint8_t *data;
        size_t   len;   /* total bytes appended            */
        size_t   off;   /* bytes already consumed          */
        size_t   cap;   /* allocated capacity              */
};

/*
 * In-memory transport + scripted responder state. This must outlive the
 * smb2_context it backs (it is referenced through ext.userdata).
 *
 * tx : app->server bytes (what libsmb2 sent), consumed by the responder.
 * rx : server->app bytes (scripted replies), consumed by the recv callback.
 *
 * The counters back the test assertions: socket_calls MUST stay 0 (proving no
 * descriptor is ever created), while bytes_sent/bytes_recvd prove real
 * bidirectional movement. saw_* record how far the engine drove the scripted
 * handshake.
 */
struct mock_transport {
        struct mock_buf tx;
        struct mock_buf rx;

        int      connected;       /* connect callback fired              */
        unsigned long socket_calls; /* socket(2) calls: always 0         */
        size_t   bytes_sent;      /* total app->server bytes             */
        size_t   bytes_recvd;     /* total server->app bytes delivered   */

        int      saw_negotiate;     /* parsed a NEGOTIATE request        */
        int      sent_negotiate_rep;/* staged the NEGOTIATE reply        */
        int      saw_session_setup; /* parsed a SESSION_SETUP request    */
        unsigned long pdus_seen;    /* complete request PDUs parsed      */

        /*
         * Full-exchange (#15) state + observation flags. The two-step
         * SESSION_SETUP and QUERY_DIRECTORY commands need a per-command step
         * counter (interim vs final / entries vs no-more-files); everything
         * else is keyed on Command alone. The saw_* flags let the test assert
         * the engine drove every stage of connect_share + opendir + teardown
         * purely through the callbacks.
         */
        int      session_setup_step;  /* 0 = interim challenge, 1 = success */
        int      query_dir_step;      /* 0 = entries, 1 = no-more-files     */
        int      saw_tree_connect;    /* parsed a TREE_CONNECT request      */
        int      saw_create;          /* parsed a CREATE request            */
        int      saw_query_directory; /* parsed a QUERY_DIRECTORY request   */
        int      saw_close;           /* parsed a CLOSE request             */
        int      saw_tree_disconnect; /* parsed a TREE_DISCONNECT request   */
        int      saw_logoff;          /* parsed a LOGOFF request            */
};

/*
 * Initialize the in-memory transport state. Must be called before
 * mock_transport_fill(). Returns 0 on success, -1 on allocation failure.
 */
int mock_transport_init(struct mock_transport *m);

/*
 * Release any buffers owned by the transport state. Safe to call on a
 * zero-initialized or already-destroyed struct.
 */
void mock_transport_destroy(struct mock_transport *m);

/*
 * Populate an smb2_external_transport with the four in-memory callbacks, wiring
 * userdata to the supplied state. After this call, hand ext to
 * smb2_set_transport(smb2, SMB2_TRANSPORT_AUTO, &ext).
 */
void mock_transport_fill(struct smb2_external_transport *ext,
                         struct mock_transport *m);

#ifdef __cplusplus
}
#endif

#endif /* !_MOCK_TRANSPORT_H_ */
