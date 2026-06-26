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

/*
 * ------------------------------------------------------------------------
 * Full-exchange templates (issue #15).
 *
 * Beyond NEGOTIATE, a complete smb2_connect_share + directory list drives:
 *   SESSION_SETUP (interim NTLM challenge) -> SESSION_SETUP (success) ->
 *   TREE_CONNECT -> CREATE (open dir) -> QUERY_DIRECTORY (entries) ->
 *   QUERY_DIRECTORY (no-more-files) -> CLOSE -> TREE_DISCONNECT -> LOGOFF.
 *
 * Every template below is a complete, UNSIGNED SMB 2.0.2 reply (zero
 * signature) keyed only on the parsed Command (+ a small per-command step
 * counter in the responder for the two-step SESSION_SETUP / QUERY_DIRECTORY
 * commands). The determinism rationale from the top of this file applies
 * unchanged: with dialect pinned to 2.0.2 and signing disabled the engine
 * neither derives a session key nor verifies a response signature, so these
 * hand-crafted replies are accepted.
 *
 * What this does NOT cover (deferred to the TCP-backed / live-server mode of
 * prog_external_exchange): SMB signing, SMB 3.x dialects, encryption (seal),
 * and real credential validation -- all of which require a genuine NTLM
 * session-key agreement and valid per-PDU signatures that a static server
 * stream cannot fabricate. The in-memory mode is therefore an honest full
 * unsigned-2.0.2 exchange, not a stand-in for the cryptographic paths.
 *
 * Shared 64-byte SMB2 sync header. CMD is the command; ST0..ST3 are the
 * 4 little-endian Status bytes; TID/SID are the low bytes of TreeId/SessionId
 * (the responder additionally patches the 8-byte MessageId at offset 24 to
 * echo the request). CreditResponse is a generous 8; only one PDU is ever in
 * flight on this path.
 */
#define MOCK_SMB2_HDR(CMD, ST0, ST1, ST2, ST3, TID, SID)                      \
        0xFE, 'S',  'M',  'B',          /* ProtocolId                      */ \
        0x40, 0x00,                     /* StructureSize = 64              */ \
        0x00, 0x00,                     /* CreditCharge = 0                */ \
        (ST0),(ST1),(ST2),(ST3),        /* Status                          */ \
        (CMD),0x00,                     /* Command                         */ \
        0x08, 0x00,                     /* CreditResponse = 8              */ \
        0x01, 0x00, 0x00, 0x00,         /* Flags = SERVER_TO_REDIR         */ \
        0x00, 0x00, 0x00, 0x00,         /* NextCommand = 0                 */ \
        0x00, 0x00, 0x00, 0x00,         /* MessageId low  (patched)        */ \
        0x00, 0x00, 0x00, 0x00,         /* MessageId high (patched)        */ \
        0x00, 0x00, 0x00, 0x00,         /* Reserved / ProcessId            */ \
        (TID),0x00, 0x00, 0x00,         /* TreeId                          */ \
        (SID),0x00, 0x00, 0x00,         /* SessionId low                   */ \
        0x00, 0x00, 0x00, 0x00,         /* SessionId high                  */ \
        0x00, 0x00, 0x00, 0x00,         /* Signature (zero - unsigned)     */ \
        0x00, 0x00, 0x00, 0x00,                                               \
        0x00, 0x00, 0x00, 0x00,                                               \
        0x00, 0x00, 0x00, 0x00

/* Fixed, anonymized identifiers baked into the later replies. */
#define MOCK_TREE_ID    0x05
#define MOCK_SESSION_ID 0x34

/*
 * Minimal raw (un-wrapped) NTLMSSP CHALLENGE_MESSAGE (MS-NLMP 2.2.1.2), 56
 * bytes: header only, empty TargetName and empty TargetInfo, fixed
 * ServerChallenge 01..08. The client only needs a well-formed challenge with a
 * readable ServerChallenge to compute its (never-validated) NTLMv2 response.
 */
#define MOCK_NTLM_CHALLENGE_LEN 56
static const uint8_t mock_ntlm_challenge[MOCK_NTLM_CHALLENGE_LEN] = {
        0x4E, 0x54, 0x4C, 0x4D,         /* "NTLM"                          */
        0x53, 0x53, 0x50, 0x00,         /* "SSP\0"                         */
        0x02, 0x00, 0x00, 0x00,         /* MessageType = CHALLENGE (2)     */
        0x00, 0x00,                     /* TargetNameLen = 0               */
        0x00, 0x00,                     /* TargetNameMaxLen = 0            */
        0x00, 0x00, 0x00, 0x00,         /* TargetNameBufferOffset = 0      */
        0x01, 0x02, 0x08, 0x00,         /* NegotiateFlags: UNICODE|NTLM|   */
                                        /*   EXTENDED_SESSIONSECURITY      */
        0x01, 0x02, 0x03, 0x04,         /* ServerChallenge (fixed)         */
        0x05, 0x06, 0x07, 0x08,
        0x00, 0x00, 0x00, 0x00,         /* Reserved                        */
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00,                     /* TargetInfoLen = 0               */
        0x00, 0x00,                     /* TargetInfoMaxLen = 0            */
        0x00, 0x00, 0x00, 0x00,         /* TargetInfoBufferOffset = 0      */
        0x00, 0x00, 0x00, 0x00,         /* Version (unused)                */
        0x00, 0x00, 0x00, 0x00
};

/*
 * SESSION_SETUP interim reply: Status = MORE_PROCESSING_REQUIRED (0xC0000016,
 * little-endian 16 00 00 C0), carrying the NTLM challenge in the security
 * buffer at offset 72 (= 64 header + 8 fixed body).
 */
static const uint8_t mock_session_setup_interim_reply[] = {
        MOCK_SMB2_HDR(SMB2_SESSION_SETUP, 0x16, 0x00, 0x00, 0xC0,
                      0x00, MOCK_SESSION_ID),
        /* ---- SESSION_SETUP reply body (8 bytes) ---- */
        0x09, 0x00,                     /* StructureSize = 9               */
        0x00, 0x00,                     /* SessionFlags = 0                */
        0x48, 0x00,                     /* SecurityBufferOffset = 72       */
        0x38, 0x00,                     /* SecurityBufferLength = 56       */
        /* ---- security buffer: NTLMSSP CHALLENGE (56 bytes) ---- */
        0x4E, 0x54, 0x4C, 0x4D, 0x53, 0x53, 0x50, 0x00,
        0x02, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x01, 0x02, 0x08, 0x00,
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

/* SESSION_SETUP final reply: Status = SUCCESS, empty security buffer. */
static const uint8_t mock_session_setup_final_reply[] = {
        MOCK_SMB2_HDR(SMB2_SESSION_SETUP, 0x00, 0x00, 0x00, 0x00,
                      0x00, MOCK_SESSION_ID),
        0x09, 0x00,                     /* StructureSize = 9               */
        0x00, 0x00,                     /* SessionFlags = 0                */
        0x00, 0x00,                     /* SecurityBufferOffset = 0        */
        0x00, 0x00                      /* SecurityBufferLength = 0        */
};

/* TREE_CONNECT reply: a DISK share, no flags. */
static const uint8_t mock_tree_connect_reply[] = {
        MOCK_SMB2_HDR(SMB2_TREE_CONNECT, 0x00, 0x00, 0x00, 0x00,
                      MOCK_TREE_ID, MOCK_SESSION_ID),
        0x10, 0x00,                     /* StructureSize = 16              */
        0x01,                           /* ShareType = DISK                */
        0x00,                           /* Reserved                        */
        0x00, 0x00, 0x00, 0x00,         /* ShareFlags = 0                  */
        0x00, 0x00, 0x00, 0x00,         /* Capabilities = 0                */
        0x00, 0x00, 0x00, 0x00          /* MaximalAccess = 0               */
};

/*
 * CREATE reply: opens the directory handle. FileId is a fixed recognizable
 * pattern the engine echoes back on QUERY_DIRECTORY / CLOSE.
 */
static const uint8_t mock_create_reply[] = {
        MOCK_SMB2_HDR(SMB2_CREATE, 0x00, 0x00, 0x00, 0x00,
                      MOCK_TREE_ID, MOCK_SESSION_ID),
        0x59, 0x00,                     /* StructureSize = 89              */
        0x00,                           /* OplockLevel = 0                 */
        0x00,                           /* Flags = 0                       */
        0x01, 0x00, 0x00, 0x00,         /* CreateAction = FILE_OPENED      */
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* CreationTime    */
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* LastAccessTime  */
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* LastWriteTime   */
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ChangeTime      */
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* AllocationSize  */
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* EndOfFile       */
        0x10, 0x00, 0x00, 0x00,         /* FileAttributes = DIRECTORY      */
        0x00, 0x00, 0x00, 0x00,         /* Reserved2                       */
        0xF1, 0xD0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* FileId (lo)     */
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* FileId (hi)     */
        0x00, 0x00, 0x00, 0x00,         /* CreateContextsOffset = 0        */
        0x00, 0x00, 0x00, 0x00          /* CreateContextsLength = 0        */
};

/*
 * QUERY_DIRECTORY reply with two FileIdFullDirectoryInformation entries the
 * test asserts byte-for-byte after readdir:
 *   1. "dir1"      DIRECTORY, EndOfFile 0
 *   2. "file1.txt" ARCHIVE,   EndOfFile 1234 (0x4D2)
 * OutputBufferOffset = 72, OutputBufferLength = 186 (0xBA) = 88 + 98.
 */
#define MOCK_QDIR_ENTRY1_SIZE 88        /* 80 fixed + 8  ("dir1")          */
#define MOCK_QDIR_ENTRY2_SIZE 98        /* 80 fixed + 18 ("file1.txt")     */
#define MOCK_QDIR_OUTPUT_LEN  (MOCK_QDIR_ENTRY1_SIZE + MOCK_QDIR_ENTRY2_SIZE)
static const uint8_t mock_query_dir_reply[] = {
        MOCK_SMB2_HDR(SMB2_QUERY_DIRECTORY, 0x00, 0x00, 0x00, 0x00,
                      MOCK_TREE_ID, MOCK_SESSION_ID),
        0x09, 0x00,                     /* StructureSize = 9               */
        0x48, 0x00,                     /* OutputBufferOffset = 72         */
        0xBA, 0x00, 0x00, 0x00,         /* OutputBufferLength = 186        */

        /* ---- entry 1: "dir1" (directory) ---- */
        0x58, 0x00, 0x00, 0x00,         /* NextEntryOffset = 88            */
        0x00, 0x00, 0x00, 0x00,         /* FileIndex                       */
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* CreationTime    */
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* LastAccessTime  */
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* LastWriteTime   */
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ChangeTime      */
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* EndOfFile = 0   */
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* AllocationSize  */
        0x10, 0x00, 0x00, 0x00,         /* FileAttributes = DIRECTORY      */
        0x08, 0x00, 0x00, 0x00,         /* FileNameLength = 8              */
        0x00, 0x00, 0x00, 0x00,         /* EaSize                          */
        0x00, 0x00, 0x00, 0x00,         /* Reserved                        */
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* FileId          */
        0x64, 0x00, 0x69, 0x00,         /* "di"                            */
        0x72, 0x00, 0x31, 0x00,         /* "r1"                            */

        /* ---- entry 2: "file1.txt" (file, size 1234) ---- */
        0x00, 0x00, 0x00, 0x00,         /* NextEntryOffset = 0 (last)      */
        0x00, 0x00, 0x00, 0x00,         /* FileIndex                       */
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* CreationTime    */
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* LastAccessTime  */
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* LastWriteTime   */
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ChangeTime      */
        0xD2, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* EndOfFile=1234  */
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* AllocationSize  */
        0x20, 0x00, 0x00, 0x00,         /* FileAttributes = ARCHIVE        */
        0x12, 0x00, 0x00, 0x00,         /* FileNameLength = 18             */
        0x00, 0x00, 0x00, 0x00,         /* EaSize                          */
        0x00, 0x00, 0x00, 0x00,         /* Reserved                        */
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* FileId          */
        0x66, 0x00, 0x69, 0x00,         /* "fi"                            */
        0x6C, 0x00, 0x65, 0x00,         /* "le"                            */
        0x31, 0x00, 0x2E, 0x00,         /* "1."                            */
        0x74, 0x00, 0x78, 0x00,         /* "tx"                            */
        0x74, 0x00                      /* "t"                             */
};

/* QUERY_DIRECTORY terminating reply: Status = NO_MORE_FILES (0x80000006). */
static const uint8_t mock_query_dir_nomore_reply[] = {
        MOCK_SMB2_HDR(SMB2_QUERY_DIRECTORY, 0x06, 0x00, 0x00, 0x80,
                      MOCK_TREE_ID, MOCK_SESSION_ID),
        0x09, 0x00,                     /* StructureSize = 9               */
        0x00, 0x00,                     /* OutputBufferOffset = 0          */
        0x00, 0x00, 0x00, 0x00          /* OutputBufferLength = 0          */
};

/* CLOSE reply (StructureSize 60). */
static const uint8_t mock_close_reply[] = {
        MOCK_SMB2_HDR(SMB2_CLOSE, 0x00, 0x00, 0x00, 0x00,
                      MOCK_TREE_ID, MOCK_SESSION_ID),
        0x3C, 0x00,                     /* StructureSize = 60              */
        0x00, 0x00,                     /* Flags = 0                       */
        0x00, 0x00, 0x00, 0x00,         /* Reserved                        */
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* CreationTime    */
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* LastAccessTime  */
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* LastWriteTime   */
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ChangeTime      */
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* AllocationSize  */
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* EndOfFile       */
        0x00, 0x00, 0x00, 0x00          /* FileAttributes                  */
};

/* TREE_DISCONNECT reply (StructureSize 4). */
static const uint8_t mock_tree_disconnect_reply[] = {
        MOCK_SMB2_HDR(SMB2_TREE_DISCONNECT, 0x00, 0x00, 0x00, 0x00,
                      MOCK_TREE_ID, MOCK_SESSION_ID),
        0x04, 0x00,                     /* StructureSize = 4               */
        0x00, 0x00                      /* Reserved                        */
};

/* LOGOFF reply (StructureSize 4). */
static const uint8_t mock_logoff_reply[] = {
        MOCK_SMB2_HDR(SMB2_LOGOFF, 0x00, 0x00, 0x00, 0x00,
                      0x00, MOCK_SESSION_ID),
        0x04, 0x00,                     /* StructureSize = 4               */
        0x00, 0x00                      /* Reserved                        */
};

#endif /* !_RECORDED_EXCHANGE_H_ */
