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
 * smb2-ls over a TEST-OWNED external transport.
 *
 * Functionally identical to prog_ls.c (parse URL, connect, opendir, print the
 * readdir loop), but the SMB2 byte stream is carried over a TCP socket the test
 * owns via smb2_set_transport(ctx, SMB2_TRANSPORT_AUTO, &ext) and the four
 * external_tcp_transport callbacks. After connecting it asserts that libsmb2
 * owns no pollable descriptor (smb2_get_fd() == SMB2_INVALID_SOCKET and
 * smb2_get_fds() reports zero fds), demonstrating that a real end-to-end ls
 * runs with no libsmb2-owned socket.
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <assert.h>
#include <inttypes.h>
#if !defined(__amigaos4__) && !defined(__AMIGA__) && !defined(__AROS__)
#include <poll.h>
#endif
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "smb2.h"
#include "libsmb2.h"
#include "libsmb2-raw.h"

#include "external_tcp_transport.h"

/*
 * The public header exposes t_socket but not the invalid-socket sentinel
 * (that lives in the internal compat.h). Mirror the documented contract here
 * on the public surface: smb2_get_fd() returns the platform's invalid socket
 * for a transport that owns no descriptor. On POSIX t_socket is int and the
 * sentinel is -1; on Windows it is SOCKET and the sentinel is INVALID_SOCKET.
 */
#if defined(_WIN32) || defined(_XBOX) || defined(__MINGW32__)
#define EXT_INVALID_SOCKET INVALID_SOCKET
#else
#define EXT_INVALID_SOCKET ((t_socket)-1)
#endif

int usage(void)
{
        fprintf(stderr, "Usage:\n"
                "prog_ls_external <smb2-url>\n\n"
                "URL format: "
                "smb://[<domain;][<username>@]<host>[:<port>]/<share>/<path>\n");
        exit(1);
}

int main(int argc, char *argv[])
{
        struct smb2_context *smb2;
        struct smb2_url *url;
        struct smb2dir *dir;
        struct smb2dirent *ent;
        struct ext_tcp t = { -1 };
        struct smb2_external_transport ext;
        const t_socket *fds;
        size_t fd_count = (size_t)-1;
        int fds_timeout = 0;
        char *link;
        int rc = 1;

        if (argc < 2) {
                usage();
        }

        smb2 = smb2_init_context();
        if (smb2 == NULL) {
                fprintf(stderr, "Failed to init context\n");
                exit(1);
        }

        url = smb2_parse_url(smb2, argv[1]);
        if (url == NULL) {
                fprintf(stderr, "Failed to parse url: %s\n",
                        smb2_get_error(smb2));
                exit(1);
        }

        /* Plug in the test-owned TCP transport BEFORE connecting. The struct
         * is copied by value into the context; the ext_tcp state t backs
         * ext.userdata and must outlive the context. */
        memset(&ext, 0, sizeof(ext));
        ext_tcp_fill(&ext, &t);
        if (smb2_set_transport(smb2, SMB2_TRANSPORT_AUTO, &ext) < 0) {
                fprintf(stderr, "smb2_set_transport failed: %s\n",
                        smb2_get_error(smb2));
                goto out_url;
        }

        smb2_set_security_mode(smb2, SMB2_NEGOTIATE_SIGNING_ENABLED);
        if (smb2_connect_share(smb2, url->server, url->share, url->user) < 0) {
                printf("smb2_connect_share failed. %s\n", smb2_get_error(smb2));
                goto out_context;
        }

        /* The exchange above ran entirely through the external callbacks. The
         * SMB engine must own no pollable descriptor: the only live socket is
         * t.fd, owned by this test. */
        assert(smb2_get_fd(smb2) == EXT_INVALID_SOCKET);
        fds = smb2_get_fds(smb2, &fd_count, &fds_timeout);
        assert(fds == NULL);
        assert(fd_count == 0);

        dir = smb2_opendir(smb2, url->path);
        if (dir == NULL) {
                printf("smb2_opendir failed. %s\n", smb2_get_error(smb2));
                goto out_disconnect;
        }

        while ((ent = smb2_readdir(smb2, dir))) {
                char *type;
                time_t mt;

                mt = (time_t)ent->st.smb2_mtime;
                switch (ent->st.smb2_type) {
                case SMB2_TYPE_LINK:
                        type = "LINK";
                        break;
                case SMB2_TYPE_FILE:
                        type = "FILE";
                        break;
                case SMB2_TYPE_DIRECTORY:
                        type = "DIRECTORY";
                        break;
                default:
                        type = "unknown";
                        break;
                }
                printf("%-20s %-9s %15"PRIu64" %s", ent->name, type,
                       ent->st.smb2_size, asctime(localtime(&mt)));
                if (ent->st.smb2_type == SMB2_TYPE_LINK) {
                        char buf[256];

                        if (url->path && url->path[0]) {
                                if (asprintf(&link, "%s/%s", url->path,
                                             ent->name) < 0) {
                                        printf("asprintf failed\n");
                                        goto out_disconnect;
                                }
                        } else {
                                if (asprintf(&link, "%s", ent->name) < 0) {
                                        printf("asprintf failed\n");
                                        goto out_disconnect;
                                }
                        }
                        if (smb2_readlink(smb2, link, buf, 256) == 0) {
                                printf("    -> [%s]\n", buf);
                        } else {
                                printf("    readlink failed\n");
                        }
                        free(link);
                }
        }

        rc = 0;
        smb2_closedir(smb2, dir);
 out_disconnect:
        smb2_disconnect_share(smb2);
 out_context:
        /* fall through */
 out_url:
        smb2_destroy_url(url);
        smb2_destroy_context(smb2);

        return rc;
}
