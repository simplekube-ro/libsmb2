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
 * Test-owned TCP transport: the four external-transport callbacks backed by a
 * plain non-blocking TCP socket created and owned by the test. This is the one
 * and only place a socket(2) is created in this fixture, and it is owned by the
 * test program, never by libsmb2.
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

#include "external_tcp_transport.h"

/*
 * connect(2) to host:port, store the descriptor in the test-owned state, and
 * switch it to non-blocking so the engine's recv callback yields EAGAIN rather
 * than stalling the single-threaded smb2_service() loop. Returns 0 on success,
 * <0 on failure. libsmb2 performs no name resolution; we do it here.
 */
static int
ext_tcp_connect(void *userdata, const char *host, int port)
{
        struct ext_tcp *t = (struct ext_tcp *)userdata;
        struct addrinfo hints, *res = NULL, *ai;
        char service[16];
        int fd = -1;
        int flags;
        int err;

        if (t == NULL || host == NULL) {
                return -1;
        }

        snprintf(service, sizeof(service), "%d", port);

        memset(&hints, 0, sizeof(hints));
        hints.ai_family = AF_UNSPEC;
        hints.ai_socktype = SOCK_STREAM;

        err = getaddrinfo(host, service, &hints, &res);
        if (err != 0) {
                return -1;
        }

        for (ai = res; ai != NULL; ai = ai->ai_next) {
                fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
                if (fd < 0) {
                        continue;
                }
                if (connect(fd, ai->ai_addr, ai->ai_addrlen) == 0) {
                        break;
                }
                close(fd);
                fd = -1;
        }

        freeaddrinfo(res);

        if (fd < 0) {
                return -1;
        }

        /* Switch to non-blocking so recv() returns EAGAIN when there is
         * nothing to read instead of blocking the service loop. */
        flags = fcntl(fd, F_GETFL, 0);
        if (flags >= 0) {
                (void)fcntl(fd, F_SETFL, flags | O_NONBLOCK);
        }

        t->fd = fd;
        return 0;
}

/*
 * send(2) up to len bytes. Returns the number of bytes sent (which may be less
 * than len for a short write -- the engine retries the remainder), or -1 with
 * errno preserved (EAGAIN/EWOULDBLOCK is the normal would-block signal).
 */
static int
ext_tcp_send(void *userdata, const uint8_t *buf, size_t len)
{
        struct ext_tcp *t = (struct ext_tcp *)userdata;
        ssize_t n;

        if (t == NULL || t->fd < 0) {
                errno = EBADF;
                return -1;
        }

        n = send(t->fd, buf, len, 0);
        if (n < 0) {
                return -1;
        }
        return (int)n;
}

/*
 * recv(2) up to max_len bytes. Returns >0 for data, 0 on peer close, or -1 with
 * errno preserved. recv(2) never returns more than max_len, satisfying the
 * external-transport contract.
 */
static int
ext_tcp_recv(void *userdata, uint8_t *buf, size_t max_len)
{
        struct ext_tcp *t = (struct ext_tcp *)userdata;
        ssize_t n;

        if (t == NULL || t->fd < 0) {
                errno = EBADF;
                return -1;
        }

        n = recv(t->fd, buf, max_len, 0);
        if (n < 0) {
                return -1;
        }
        return (int)n;
}

/*
 * close(2) the test-owned descriptor and reset it. Returns 0. libsmb2 never
 * closes a real descriptor on the external path; tearing it down is the test's
 * job, performed here.
 */
static int
ext_tcp_close(void *userdata)
{
        struct ext_tcp *t = (struct ext_tcp *)userdata;

        if (t == NULL) {
                return 0;
        }
        if (t->fd >= 0) {
                close(t->fd);
                t->fd = -1;
        }
        return 0;
}

void
ext_tcp_fill(struct smb2_external_transport *ext, struct ext_tcp *t)
{
        ext->userdata = t;
        ext->connect = ext_tcp_connect;
        ext->send = ext_tcp_send;
        ext->recv = ext_tcp_recv;
        ext->close = ext_tcp_close;
}
