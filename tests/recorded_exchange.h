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
 * Recorded / scripted server-exchange fixture for the in-memory mock transport.
 *
 * These are the canned server->client response templates the mock responder
 * replays. They are self-contained C arrays so the test needs no runtime file
 * I/O and no live server. Each array is one complete SMB2 message WITHOUT the
 * 4-byte direct-TCP StreamProtocolLength (SPL) prefix; the responder prepends
 * the big-endian SPL and patches in the request's MessageId (the engine matches
 * replies to in-flight requests by MessageId) before staging it for delivery.
 *
 * Determinism (see the comment block in prog_mock.c):
 *   - Dialect is pinned to SMB 2.0.2: no negotiate contexts, no SMB3.1.1
 *     pre-auth integrity salts.
 *   - Signing is disabled: the engine does not verify response signatures, so
 *     the zero-signature templates below are accepted.
 *   - Every byte that varies per run (the client GUID / NTLM challenge /
 *     timestamps) lives in the *client's* request, which the responder never
 *     byte-compares; it keys only on the parsed Command + MessageId. The
 *     server-side view encoded here is therefore fully deterministic.
 *
 * NEGOTIATE reply layout (64-byte SMB2 header + 64-byte fixed body, dialect
 * 0x0202, empty security buffer, signing-not-required). Anonymized: server GUID
 * is a fixed ASCII tag, SystemTime / ServerStartTime are zeroed.
 */

#ifndef _RECORDED_EXCHANGE_H_
#define _RECORDED_EXCHANGE_H_

#include <stdint.h>

/* Byte offset of the 8-byte MessageId inside an SMB2 header (and thus inside
 * each template below), patched by the responder to echo the request. */
#define MOCK_HDR_MESSAGE_ID_OFF 24

/* Hand-crafted minimal SMB 2.0.2 NEGOTIATE response (unsigned). */
static const uint8_t mock_negotiate_reply[] = {
        /* ---- SMB2 header (64 bytes) ---- */
        0xFE, 'S',  'M',  'B',          /* [0]  ProtocolId                    */
        0x40, 0x00,                     /* [4]  StructureSize = 64            */
        0x00, 0x00,                     /* [6]  CreditCharge = 0              */
        0x00, 0x00, 0x00, 0x00,         /* [8]  Status = STATUS_SUCCESS       */
        0x00, 0x00,                     /* [12] Command = SMB2_NEGOTIATE      */
        0x08, 0x00,                     /* [14] CreditResponse = 8            */
        0x01, 0x00, 0x00, 0x00,         /* [16] Flags = SERVER_TO_REDIR       */
        0x00, 0x00, 0x00, 0x00,         /* [20] NextCommand = 0               */
        0x00, 0x00, 0x00, 0x00,         /* [24] MessageId (patched)           */
        0x00, 0x00, 0x00, 0x00,         /* [28]   ... high dword              */
        0x00, 0x00, 0x00, 0x00,         /* [32] Reserved / ProcessId          */
        0x00, 0x00, 0x00, 0x00,         /* [36] TreeId = 0                    */
        0x00, 0x00, 0x00, 0x00,         /* [40] SessionId                     */
        0x00, 0x00, 0x00, 0x00,         /* [44]   ... high dword              */
        0x00, 0x00, 0x00, 0x00,         /* [48] Signature                     */
        0x00, 0x00, 0x00, 0x00,         /* [52]   ...                         */
        0x00, 0x00, 0x00, 0x00,         /* [56]   ...                         */
        0x00, 0x00, 0x00, 0x00,         /* [60]   ...                         */

        /* ---- NEGOTIATE reply body (64 bytes) ---- */
        0x41, 0x00,                     /* [b0]  StructureSize = 65           */
        0x00, 0x00,                     /* [b2]  SecurityMode = 0             */
        0x02, 0x02,                     /* [b4]  DialectRevision = 0x0202     */
        0x00, 0x00,                     /* [b6]  NegotiateContextCount = 0    */
        'M',  'O',  'C',  'K',          /* [b8]  ServerGuid (anonymized tag)  */
        '-',  'S',  'M',  'B',
        '2',  '-',  'G',  'U',
        'I',  'D',  '0',  '1',
        0x00, 0x00, 0x00, 0x00,         /* [b24] Capabilities = 0             */
        0x00, 0x00, 0x10, 0x00,         /* [b28] MaxTransactSize = 0x00100000 */
        0x00, 0x00, 0x10, 0x00,         /* [b32] MaxReadSize  = 0x00100000    */
        0x00, 0x00, 0x10, 0x00,         /* [b36] MaxWriteSize = 0x00100000    */
        0x00, 0x00, 0x00, 0x00,         /* [b40] SystemTime (anonymized 0)    */
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,         /* [b48] ServerStartTime (anon. 0)    */
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00,                     /* [b56] SecurityBufferOffset = 0     */
        0x00, 0x00,                     /* [b58] SecurityBufferLength = 0     */
        0x00, 0x00, 0x00, 0x00          /* [b60] NegotiateContextOffset = 0   */
};

#endif /* !_RECORDED_EXCHANGE_H_ */
