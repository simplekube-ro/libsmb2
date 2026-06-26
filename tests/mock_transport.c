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
 * Pure in-memory loopback transport: the four external-transport callbacks
 * backed by two in-memory byte queues plus a scripted server responder. No
 * socket(2) is created here or anywhere on this path -- the SMB2 byte stream
 * never leaves process memory. See mock_transport.h and recorded_exchange.h.
 */

#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "mock_transport.h"
#include "recorded_exchange.h"

/* Direct-TCP StreamProtocolLength prefix size and SMB2 header offsets we read
 * from a request to drive the scripted responder. These mirror the on-wire
 * layout libsmb2 itself encodes; we re-derive them here so the fixture depends
 * only on the public headers. */
#define MOCK_SPL_SIZE        4
#define MOCK_SMB2_HEADER_SIZE 64
#define MOCK_HDR_COMMAND_OFF 12

/* ------------------------------------------------------------------ */
/* Tiny append/consume byte buffer helpers.                            */
/* ------------------------------------------------------------------ */

static int
mock_buf_append(struct mock_buf *b, const uint8_t *src, size_t n)
{
        if (n == 0) {
                return 0;
        }
        if (b->len + n > b->cap) {
                size_t ncap = b->cap ? b->cap : 256;
                uint8_t *nd;

                while (ncap < b->len + n) {
                        ncap *= 2;
                }
                nd = realloc(b->data, ncap);
                if (nd == NULL) {
                        return -1;
                }
                b->data = nd;
                b->cap = ncap;
        }
        memcpy(b->data + b->len, src, n);
        b->len += n;
        return 0;
}

/* Bytes available to consume (appended but not yet read). */
static size_t
mock_buf_avail(const struct mock_buf *b)
{
        return b->len - b->off;
}

/* ------------------------------------------------------------------ */
/* Little/big-endian readers (no host-endianness assumptions).         */
/* ------------------------------------------------------------------ */

static uint32_t
mock_be32(const uint8_t *p)
{
        return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
               ((uint32_t)p[2] << 8)  |  (uint32_t)p[3];
}

static uint16_t
mock_le16(const uint8_t *p)
{
        return (uint16_t)((uint16_t)p[0] | ((uint16_t)p[1] << 8));
}

/* ------------------------------------------------------------------ */
/* Scripted server responder.                                          */
/* ------------------------------------------------------------------ */

/*
 * Stage a server->app reply: prepend the big-endian SPL (length of the SMB2
 * message), copy the template, and patch the request's MessageId so the engine
 * correlates the reply with the in-flight request. Returns 0 / -1.
 */
static int
mock_stage_reply(struct mock_transport *m, const uint8_t *msg, size_t msg_len,
                 const uint8_t *msg_id8)
{
        uint8_t spl[MOCK_SPL_SIZE];
        size_t reply_start;

        spl[0] = (uint8_t)((msg_len >> 24) & 0xff);
        spl[1] = (uint8_t)((msg_len >> 16) & 0xff);
        spl[2] = (uint8_t)((msg_len >> 8)  & 0xff);
        spl[3] = (uint8_t)( msg_len        & 0xff);

        reply_start = m->rx.len;
        if (mock_buf_append(&m->rx, spl, MOCK_SPL_SIZE) < 0) {
                return -1;
        }
        if (mock_buf_append(&m->rx, msg, msg_len) < 0) {
                return -1;
        }
        /* Patch MessageId in the just-appended copy (after the SPL). */
        memcpy(m->rx.data + reply_start + MOCK_SPL_SIZE + MOCK_HDR_MESSAGE_ID_OFF,
               msg_id8, 8);
        return 0;
}

/*
 * React to one fully-reassembled request PDU. msg points at the SMB2 message
 * (no SPL), msg_len bytes long. The responder keys only on the parsed Command +
 * MessageId, never on the request's random bytes (client GUID / NTLM challenge
 * / timestamps), which keeps the server view deterministic.
 */
static int
mock_handle_request(struct mock_transport *m, const uint8_t *msg, size_t msg_len)
{
        uint16_t command;
        const uint8_t *msg_id8;

        if (msg_len < MOCK_SMB2_HEADER_SIZE) {
                return 0; /* not an SMB2 message we understand; ignore */
        }
        if (msg[0] != 0xFE || msg[1] != 'S' || msg[2] != 'M' || msg[3] != 'B') {
                return 0; /* not an SMB2 header (e.g. SMB1 negotiate); ignore */
        }

        command = mock_le16(msg + MOCK_HDR_COMMAND_OFF);
        msg_id8 = msg + MOCK_HDR_MESSAGE_ID_OFF;
        m->pdus_seen++;

        switch (command) {
        case SMB2_NEGOTIATE:
                m->saw_negotiate = 1;
                if (mock_stage_reply(m, mock_negotiate_reply,
                                     sizeof(mock_negotiate_reply),
                                     msg_id8) < 0) {
                        return -1;
                }
                m->sent_negotiate_rep = 1;
                break;
        case SMB2_SESSION_SETUP:
                /*
                 * NTLM is a two-step flow. The first SESSION_SETUP carries the
                 * client's NTLMSSP type-1 token; we answer with an interim
                 * reply (MORE_PROCESSING_REQUIRED + a canned type-2 challenge).
                 * The engine then emits a second SESSION_SETUP (type-3), which
                 * we answer with an unconditional success. We never validate
                 * the client's response -- with signing off the engine never
                 * confirms the session key either, so the credential path
                 * completes deterministically.
                 */
                m->saw_session_setup = 1;
                if (m->session_setup_step == 0) {
                        if (mock_stage_reply(m,
                                     mock_session_setup_interim_reply,
                                     sizeof(mock_session_setup_interim_reply),
                                     msg_id8) < 0) {
                                return -1;
                        }
                        m->session_setup_step = 1;
                } else {
                        if (mock_stage_reply(m,
                                     mock_session_setup_final_reply,
                                     sizeof(mock_session_setup_final_reply),
                                     msg_id8) < 0) {
                                return -1;
                        }
                }
                break;
        case SMB2_TREE_CONNECT:
                m->saw_tree_connect = 1;
                if (mock_stage_reply(m, mock_tree_connect_reply,
                                     sizeof(mock_tree_connect_reply),
                                     msg_id8) < 0) {
                        return -1;
                }
                break;
        case SMB2_CREATE:
                m->saw_create = 1;
                if (mock_stage_reply(m, mock_create_reply,
                                     sizeof(mock_create_reply), msg_id8) < 0) {
                        return -1;
                }
                break;
        case SMB2_QUERY_DIRECTORY:
                /*
                 * First query returns the crafted directory entries; the engine
                 * then asks for more, which we answer with NO_MORE_FILES so it
                 * closes the handle and finishes the listing.
                 */
                m->saw_query_directory = 1;
                if (m->query_dir_step == 0) {
                        if (mock_stage_reply(m, mock_query_dir_reply,
                                     sizeof(mock_query_dir_reply),
                                     msg_id8) < 0) {
                                return -1;
                        }
                        m->query_dir_step = 1;
                } else {
                        if (mock_stage_reply(m, mock_query_dir_nomore_reply,
                                     sizeof(mock_query_dir_nomore_reply),
                                     msg_id8) < 0) {
                                return -1;
                        }
                }
                break;
        case SMB2_CLOSE:
                m->saw_close = 1;
                if (mock_stage_reply(m, mock_close_reply,
                                     sizeof(mock_close_reply), msg_id8) < 0) {
                        return -1;
                }
                break;
        case SMB2_TREE_DISCONNECT:
                m->saw_tree_disconnect = 1;
                if (mock_stage_reply(m, mock_tree_disconnect_reply,
                                     sizeof(mock_tree_disconnect_reply),
                                     msg_id8) < 0) {
                        return -1;
                }
                break;
        case SMB2_LOGOFF:
                m->saw_logoff = 1;
                if (mock_stage_reply(m, mock_logoff_reply,
                                     sizeof(mock_logoff_reply), msg_id8) < 0) {
                        return -1;
                }
                break;
        default:
                break;
        }
        return 0;
}

/*
 * Drain every complete direct-TCP framed PDU currently buffered in tx and feed
 * it to the responder. A PDU is complete once tx holds its 4-byte SPL plus the
 * SPL-declared body. Partial PDUs (the engine writes the SPL/header/body as
 * separate iovecs) are left buffered until the rest arrives.
 */
static int
mock_pump(struct mock_transport *m)
{
        while (mock_buf_avail(&m->tx) >= MOCK_SPL_SIZE) {
                const uint8_t *base = m->tx.data + m->tx.off;
                uint32_t spl = mock_be32(base);

                if (mock_buf_avail(&m->tx) < (size_t)MOCK_SPL_SIZE + spl) {
                        break; /* wait for the rest of this PDU */
                }
                if (mock_handle_request(m, base + MOCK_SPL_SIZE, spl) < 0) {
                        return -1;
                }
                m->tx.off += MOCK_SPL_SIZE + spl;
        }
        return 0;
}

/* ------------------------------------------------------------------ */
/* External-transport callbacks.                                       */
/* ------------------------------------------------------------------ */

/*
 * "connect": no socket, no name resolution -- just record that the engine asked
 * to connect and mark the in-memory transport up. socket_calls is intentionally
 * left at 0 to make the "owns no socket" assertion enforceable.
 */
static int
mock_connect(void *userdata, const char *host, int port)
{
        struct mock_transport *m = (struct mock_transport *)userdata;

        (void)host;
        (void)port;
        if (m == NULL) {
                return -1;
        }
        m->connected = 1;
        return 0;
}

/*
 * "send": append the bytes the engine emitted to the tx queue, then let the
 * responder react to any now-complete request PDU. Always reports a full write
 * (never short) to keep the exchange deterministic.
 */
static int
mock_send(void *userdata, const uint8_t *buf, size_t len)
{
        struct mock_transport *m = (struct mock_transport *)userdata;

        if (m == NULL || (buf == NULL && len != 0)) {
                errno = EINVAL;
                return -1;
        }
        if (mock_buf_append(&m->tx, buf, len) < 0) {
                errno = ENOMEM;
                return -1;
        }
        m->bytes_sent += len;
        if (mock_pump(m) < 0) {
                errno = ENOMEM;
                return -1;
        }
        return (int)len;
}

/*
 * "recv": deliver staged server->app bytes, never more than max_len. When the
 * rx queue is empty, report EAGAIN (-1) -- the same would-block signal a
 * non-blocking socket gives -- so the engine's receive leaf loops without
 * busy-failing instead of seeing a 0-length peer close.
 */
static int
mock_recv(void *userdata, uint8_t *buf, size_t max_len)
{
        struct mock_transport *m = (struct mock_transport *)userdata;
        size_t avail;
        size_t n;

        if (m == NULL || buf == NULL) {
                errno = EINVAL;
                return -1;
        }
        avail = mock_buf_avail(&m->rx);
        if (avail == 0) {
                errno = EAGAIN;
                return -1;
        }
        n = (max_len < avail) ? max_len : avail;
        memcpy(buf, m->rx.data + m->rx.off, n);
        m->rx.off += n;
        m->bytes_recvd += n;
        return (int)n;
}

/*
 * "close": tear down the in-memory transport. Buffers are released by
 * mock_transport_destroy(); here we only reset the consume cursors and mark the
 * transport down. No real descriptor is ever closed.
 */
static int
mock_close(void *userdata)
{
        struct mock_transport *m = (struct mock_transport *)userdata;

        if (m == NULL) {
                return 0;
        }
        m->connected = 0;
        m->tx.off = m->tx.len;
        m->rx.off = m->rx.len;
        return 0;
}

/* ------------------------------------------------------------------ */
/* Public fixture API.                                                 */
/* ------------------------------------------------------------------ */

int
mock_transport_init(struct mock_transport *m)
{
        if (m == NULL) {
                return -1;
        }
        memset(m, 0, sizeof(*m));
        return 0;
}

void
mock_transport_destroy(struct mock_transport *m)
{
        if (m == NULL) {
                return;
        }
        free(m->tx.data);
        free(m->rx.data);
        memset(m, 0, sizeof(*m));
}

void
mock_transport_fill(struct smb2_external_transport *ext,
                    struct mock_transport *m)
{
        ext->userdata = m;
        ext->connect = mock_connect;
        ext->send = mock_send;
        ext->recv = mock_recv;
        ext->close = mock_close;
}
