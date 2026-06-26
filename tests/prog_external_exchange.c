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
 * Headline decoupling test (issue #15): a FULL SMB exchange -- connect_share
 * (NEGOTIATE -> NTLM SESSION_SETUP x2 -> TREE_CONNECT), a directory listing
 * (CREATE -> QUERY_DIRECTORY -> CLOSE), and clean teardown (TREE_DISCONNECT ->
 * LOGOFF) -- driven entirely through the four external-transport callbacks via
 * smb2_set_transport(). It proves libsmb2 needs no internally-owned socket
 * (RandomPlayer#344 acceptance criterion #2).
 *
 * The SAME program runs two ways:
 *
 *   prog_external_exchange --inmemory
 *       Network-free: the callbacks are backed by in-memory byte queues and a
 *       scripted server responder (mock_transport.c / recorded_exchange.h). No
 *       socket(2) is ever created, by libsmb2 or by the fixture. The directory
 *       entries are asserted byte-for-byte against the crafted reply. Safe to
 *       run unconditionally in CI.
 *
 *   prog_external_exchange <smb2-url>
 *       TCP-backed: the callbacks ride a real, TEST-owned non-blocking TCP
 *       socket (external_tcp_transport.c) to a live server. libsmb2 still owns
 *       no descriptor (asserted via smb2_get_fd/smb2_get_fds). This exercises
 *       the genuine signed/credential-validated crypto path that the in-memory
 *       fixture deliberately does not fabricate; the listing is asserted only
 *       for clean iteration + teardown since the share contents are unknown.
 *
 * Verification in --inmemory mode is real program control flow (if/goto + rc),
 * never assert(), so a Release / -DNDEBUG build still fails a broken exchange.
 * The OK banner and rc=0 are reached only after every check passes.
 *
 * Determinism of the in-memory path (why it is honest, not a no-op): dialect
 * pinned to SMB 2.0.2 + signing off means the engine neither derives a session
 * key nor verifies response signatures; the responder keys only on the parsed
 * Command (+ a step counter), never on the client's per-run-random bytes. See
 * the comment blocks in recorded_exchange.h and mock_transport.h.
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <inttypes.h>
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
#include "external_tcp_transport.h"

/*
 * The public header exposes t_socket but not the invalid-socket sentinel (that
 * lives in the internal compat.h). Mirror the documented public contract:
 * smb2_get_fd() returns the platform's invalid socket for a transport that owns
 * no descriptor. On POSIX t_socket is int and the sentinel is -1.
 */
#if defined(_WIN32) || defined(_XBOX) || defined(__MINGW32__)
#define EXT_INVALID_SOCKET INVALID_SOCKET
#else
#define EXT_INVALID_SOCKET ((t_socket)-1)
#endif

/* Bound on hand-pumped service iterations per phase: the deterministic
 * exchange completes in a handful of iterations; this only guards against a
 * regression that would otherwise spin forever. */
#define EXCH_MAX_ITERS 512

struct done_state {
        int finished;
        int status;
        struct smb2dir *dir;
};

static void
op_done_cb(struct smb2_context *smb2, int status,
           void *command_data, void *private_data)
{
        struct done_state *d = private_data;

        (void)smb2;
        d->finished = 1;
        d->status = status;
        /* For opendir, command_data is the smb2dir handle on success. */
        if (status == 0 && command_data != NULL) {
                d->dir = command_data;
        }
}

/*
 * Hand-drive the read/write state machine (no sockets, no poll) until the
 * supplied done flag is set or the iteration bound is hit. Returns 0 on
 * success, -1 if smb2_service failed or the bound was exceeded.
 */
static int
pump_until(struct smb2_context *smb2, const int *finished)
{
        int i;

        for (i = 0; i < EXCH_MAX_ITERS; i++) {
                int events = smb2_which_events(smb2);

                if (smb2_service(smb2, events) < 0) {
                        fprintf(stderr, "FAIL: smb2_service: %s\n",
                                smb2_get_error(smb2));
                        return -1;
                }
                if (*finished) {
                        return 0;
                }
        }
        fprintf(stderr, "FAIL: exchange did not complete within %d iters\n",
                EXCH_MAX_ITERS);
        return -1;
}

/* Confirm libsmb2 exposes no pollable descriptor of its own. */
static int
assert_no_libsmb2_socket(struct smb2_context *smb2)
{
        const t_socket *fds;
        size_t fd_count = (size_t)-1;
        int fds_timeout = 0;

        if (smb2_get_fd(smb2) != EXT_INVALID_SOCKET) {
                fprintf(stderr, "FAIL: smb2_get_fd() returned a valid socket\n");
                return -1;
        }
        fds = smb2_get_fds(smb2, &fd_count, &fds_timeout);
        if (fds != NULL || fd_count != 0) {
                fprintf(stderr,
                        "FAIL: smb2_get_fds() exposed %zu descriptor(s)\n",
                        fd_count);
                return -1;
        }
        return 0;
}

/* ------------------------------------------------------------------ */
/* In-memory (network-free) mode.                                      */
/* ------------------------------------------------------------------ */

static int
check_entries(struct smb2_context *smb2, struct smb2dir *dir)
{
        struct smb2dirent *ent;
        int found_dir = 0;
        int found_file = 0;
        int rc = -1;

        while ((ent = smb2_readdir(smb2, dir)) != NULL) {
                if (strcmp(ent->name, "dir1") == 0) {
                        found_dir = 1;
                        if (ent->st.smb2_type != SMB2_TYPE_DIRECTORY) {
                                fprintf(stderr, "FAIL: dir1 wrong type %d\n",
                                        (int)ent->st.smb2_type);
                                goto out;
                        }
                        if (ent->st.smb2_size != 0) {
                                fprintf(stderr,
                                        "FAIL: dir1 wrong size %"PRIu64"\n",
                                        ent->st.smb2_size);
                                goto out;
                        }
                } else if (strcmp(ent->name, "file1.txt") == 0) {
                        found_file = 1;
                        if (ent->st.smb2_type != SMB2_TYPE_FILE) {
                                fprintf(stderr,
                                        "FAIL: file1.txt wrong type %d\n",
                                        (int)ent->st.smb2_type);
                                goto out;
                        }
                        if (ent->st.smb2_size != 1234) {
                                fprintf(stderr,
                                        "FAIL: file1.txt wrong size "
                                        "%"PRIu64"\n", ent->st.smb2_size);
                                goto out;
                        }
                } else {
                        fprintf(stderr, "FAIL: unexpected dir entry '%s'\n",
                                ent->name);
                        goto out;
                }
        }

        if (!found_dir) {
                fprintf(stderr, "FAIL: 'dir1' missing from readdir\n");
                goto out;
        }
        if (!found_file) {
                fprintf(stderr, "FAIL: 'file1.txt' missing from readdir\n");
                goto out;
        }
        rc = 0;
 out:
        return rc;
}

static int
run_inmemory(void)
{
        struct smb2_context *smb2;
        struct mock_transport m;
        struct smb2_external_transport ext;
        struct done_state conn, od, disc;
        struct smb2dir *dir = NULL;
        int rc = 1;

        if (mock_transport_init(&m) < 0) {
                fprintf(stderr, "FAIL: mock_transport_init\n");
                return 1;
        }

        smb2 = smb2_init_context();
        if (smb2 == NULL) {
                fprintf(stderr, "FAIL: smb2_init_context\n");
                mock_transport_destroy(&m);
                return 1;
        }

        /* Install the in-memory transport BEFORE connecting. ext is copied by
         * value; the mock state m backs ext.userdata and must outlive smb2. */
        memset(&ext, 0, sizeof(ext));
        mock_transport_fill(&ext, &m);
        if (smb2_set_transport(smb2, SMB2_TRANSPORT_AUTO, &ext) < 0) {
                fprintf(stderr, "FAIL: smb2_set_transport: %s\n",
                        smb2_get_error(smb2));
                goto out;
        }

        /* Pin the deterministic path: dialect 2.0.2, signing off, NTLM. */
        smb2_set_security_mode(smb2, 0);
        smb2_set_version(smb2, SMB2_VERSION_0202);
        smb2_set_authentication(smb2, SMB2_SEC_NTLMSSP);
        smb2_set_user(smb2, "mockuser");
        smb2_set_password(smb2, "mockpass");

        /* --- connect_share: NEGOTIATE -> SESSION_SETUP x2 -> TREE_CONNECT --- */
        memset(&conn, 0, sizeof(conn));
        if (smb2_connect_share_async(smb2, "mockhost", "share", "mockuser",
                                     op_done_cb, &conn) < 0) {
                fprintf(stderr, "FAIL: smb2_connect_share_async: %s\n",
                        smb2_get_error(smb2));
                goto out;
        }
        if (pump_until(smb2, &conn.finished) < 0) {
                goto out;
        }
        if (conn.status != 0) {
                fprintf(stderr, "FAIL: connect_share status %d: %s\n",
                        conn.status, smb2_get_error(smb2));
                goto out;
        }

        /* The full handshake crossed the callbacks. Prove libsmb2 owns no fd. */
        if (assert_no_libsmb2_socket(smb2) < 0) {
                goto out;
        }
        if (m.socket_calls != 0) {
                fprintf(stderr, "FAIL: mock created %lu socket(s)\n",
                        m.socket_calls);
                goto out;
        }
        if (m.connected != 1) {
                fprintf(stderr, "FAIL: connect callback was not invoked\n");
                goto out;
        }
        if (m.bytes_sent == 0 || m.bytes_recvd == 0) {
                fprintf(stderr, "FAIL: no bidirectional byte movement "
                        "(sent=%zu recvd=%zu)\n", m.bytes_sent, m.bytes_recvd);
                goto out;
        }
        if (!m.saw_negotiate || !m.saw_session_setup || !m.saw_tree_connect) {
                fprintf(stderr, "FAIL: connect_share did not drive all stages "
                        "(neg=%d ss=%d tcon=%d)\n", m.saw_negotiate,
                        m.saw_session_setup, m.saw_tree_connect);
                goto out;
        }

        /* --- opendir: CREATE -> QUERY_DIRECTORY (entries + no-more) -> CLOSE - */
        memset(&od, 0, sizeof(od));
        if (smb2_opendir_async(smb2, "", op_done_cb, &od) < 0) {
                fprintf(stderr, "FAIL: smb2_opendir_async: %s\n",
                        smb2_get_error(smb2));
                goto out;
        }
        if (pump_until(smb2, &od.finished) < 0) {
                goto out;
        }
        if (od.status != 0 || od.dir == NULL) {
                fprintf(stderr, "FAIL: opendir status %d: %s\n",
                        od.status, smb2_get_error(smb2));
                goto out;
        }
        dir = od.dir;

        if (!m.saw_create || !m.saw_query_directory || !m.saw_close) {
                fprintf(stderr, "FAIL: opendir did not drive all stages "
                        "(create=%d qdir=%d close=%d)\n", m.saw_create,
                        m.saw_query_directory, m.saw_close);
                goto out;
        }

        /* Byte-for-byte assertion of the crafted directory entries. */
        if (check_entries(smb2, dir) < 0) {
                goto out;
        }
        smb2_closedir(smb2, dir);
        dir = NULL;

        /* --- teardown: TREE_DISCONNECT -> LOGOFF -> external close --- */
        memset(&disc, 0, sizeof(disc));
        if (smb2_disconnect_share_async(smb2, op_done_cb, &disc) < 0) {
                fprintf(stderr, "FAIL: smb2_disconnect_share_async: %s\n",
                        smb2_get_error(smb2));
                goto out;
        }
        if (pump_until(smb2, &disc.finished) < 0) {
                goto out;
        }
        if (!m.saw_tree_disconnect || !m.saw_logoff) {
                fprintf(stderr, "FAIL: teardown did not drive all stages "
                        "(tdis=%d logoff=%d)\n", m.saw_tree_disconnect,
                        m.saw_logoff);
                goto out;
        }
        if (m.connected != 0) {
                fprintf(stderr, "FAIL: external close callback did not fire\n");
                goto out;
        }
        if (m.socket_calls != 0) {
                fprintf(stderr, "FAIL: mock created %lu socket(s) overall\n",
                        m.socket_calls);
                goto out;
        }

        rc = 0;
        printf("in-memory full exchange: OK\n");
        printf("  sockets created            : %lu\n", m.socket_calls);
        printf("  app->server bytes (sent)   : %zu\n", m.bytes_sent);
        printf("  server->app bytes (recvd)  : %zu\n", m.bytes_recvd);
        printf("  request PDUs parsed by mock: %lu\n", m.pdus_seen);
        printf("  smb2_get_fd()              : invalid (no socket)\n");
        printf("  stages: NEGOTIATE SESSION_SETUPx2 TREE_CONNECT CREATE\n");
        printf("          QUERY_DIRECTORY CLOSE TREE_DISCONNECT LOGOFF\n");
        printf("  readdir asserted: dir1 (DIRECTORY), file1.txt (FILE,1234)\n");

 out:
        if (dir != NULL) {
                smb2_closedir(smb2, dir);
        }
        smb2_destroy_context(smb2);
        mock_transport_destroy(&m);
        return rc;
}

/* ------------------------------------------------------------------ */
/* TCP-backed mode (live server, test-owned socket).                   */
/* ------------------------------------------------------------------ */

static int
run_tcp(const char *urlstr)
{
        struct smb2_context *smb2;
        struct smb2_url *url;
        struct smb2dir *dir;
        struct smb2dirent *ent;
        struct ext_tcp t = { -1 };
        struct smb2_external_transport ext;
        unsigned long count = 0;
        int rc = 1;

        smb2 = smb2_init_context();
        if (smb2 == NULL) {
                fprintf(stderr, "FAIL: smb2_init_context\n");
                return 1;
        }

        url = smb2_parse_url(smb2, urlstr);
        if (url == NULL) {
                fprintf(stderr, "FAIL: parse url: %s\n", smb2_get_error(smb2));
                smb2_destroy_context(smb2);
                return 1;
        }

        /* Plug in the test-owned TCP transport BEFORE connecting. */
        memset(&ext, 0, sizeof(ext));
        ext_tcp_fill(&ext, &t);
        if (smb2_set_transport(smb2, SMB2_TRANSPORT_AUTO, &ext) < 0) {
                fprintf(stderr, "FAIL: smb2_set_transport: %s\n",
                        smb2_get_error(smb2));
                goto out;
        }

        smb2_set_security_mode(smb2, SMB2_NEGOTIATE_SIGNING_ENABLED);
        if (smb2_connect_share(smb2, url->server, url->share, url->user) < 0) {
                fprintf(stderr, "FAIL: connect_share: %s\n",
                        smb2_get_error(smb2));
                goto out;
        }

        /* The genuine signed handshake ran over the test-owned socket; libsmb2
         * still owns no pollable descriptor. */
        if (assert_no_libsmb2_socket(smb2) < 0) {
                goto out_disconnect;
        }

        dir = smb2_opendir(smb2, url->path ? url->path : "");
        if (dir == NULL) {
                fprintf(stderr, "FAIL: opendir: %s\n", smb2_get_error(smb2));
                goto out_disconnect;
        }
        while ((ent = smb2_readdir(smb2, dir)) != NULL) {
                count++;
        }
        smb2_closedir(smb2, dir);

        rc = 0;
        printf("tcp full exchange: OK (%lu entries, libsmb2 owns no socket)\n",
               count);

 out_disconnect:
        smb2_disconnect_share(smb2);
 out:
        smb2_destroy_url(url);
        smb2_destroy_context(smb2);
        return rc;
}

static void
usage(void)
{
        fprintf(stderr,
                "Usage:\n"
                "  prog_external_exchange --inmemory      (network-free)\n"
                "  prog_external_exchange <smb2-url>      (live server)\n");
}

int main(int argc, char *argv[])
{
        if (argc < 2) {
                usage();
                return 1;
        }
        if (strcmp(argv[1], "--inmemory") == 0) {
                return run_inmemory();
        }
        return run_tcp(argv[1]);
}
