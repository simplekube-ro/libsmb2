# External Transport & Timeout API — Public Guide

> Companion to `docs/transport-abstraction-plan.md` (design) and
> `docs/transport-internals.md` (engine-internal mechanics). This document is the
> Stage-2 gate deliverable for **simplekube-ro/libsmb2#12**: it documents the
> public, library-type-free API an application uses to carry SMB2 over a transport
> that libsmb2 does not implement itself (for example SMB-over-QUIC), plus the
> timer/timeout API that lets an event loop service that transport on time.
>
> Everything below is declared in `include/smb2/libsmb2.h`; this guide expands on
> the header doc comments and shows how the pieces fit together. The internal
> receive state machine, ops-table dispatch, and `smb2_transport_is_connected()`
> plumbing are described in `docs/transport-internals.md` and are **not** repeated
> here.

## 1. Overview

By default a context speaks SMB2 over a TCP socket that libsmb2 owns. Stage 2 adds
a second, application-supplied transport path: the application implements four
plain byte-oriented callbacks (connect / send / recv / close), hands them to
libsmb2 with `smb2_set_transport()`, and then drives the session from its own
event loop. Because the external transport owns no pollable file descriptor, the
application also uses the timeout API (`smb2_get_timeout()` /
`smb2_service_timeout()`) to bound its wait and to run timer-driven work.

The public surface is deliberately minimal and carries **no** QUIC/TLS library
type — every callback exchanges raw `uint8_t` buffers (see §6).

## 2. Transport selectors

```c
#define SMB2_TRANSPORT_TCP   0
#define SMB2_TRANSPORT_QUIC  1
#define SMB2_TRANSPORT_AUTO  2
```

| Selector | Meaning |
| --- | --- |
| `SMB2_TRANSPORT_TCP`  | The built-in TCP transport. This is the default (a zero-initialized context already means "TCP"). `ext` is ignored and may be `NULL`. |
| `SMB2_TRANSPORT_QUIC` | The application-supplied (external) transport. `ext` must be non-`NULL` and provide non-`NULL` `connect`/`send`/`recv`/`close` callbacks. |
| `SMB2_TRANSPORT_AUTO` | Use the external transport when `ext` is non-`NULL` (validated as for `QUIC`); otherwise fall back to the built-in TCP transport. |

`SMB2_TRANSPORT_QUIC` is named for its motivating use case (SMB-over-QUIC) but the
mechanism is transport-agnostic: any application-supplied byte stream works.

## 3. `struct smb2_external_transport`

```c
struct smb2_external_transport {
        void *userdata;
        int (*connect)(void *userdata, const char *host, int port);
        int (*send)(void *userdata, const uint8_t *buf, size_t len);
        int (*recv)(void *userdata, uint8_t *buf, size_t max_len);
        int (*close)(void *userdata);
};
```

Each callback receives the opaque `userdata` pointer supplied here. Contracts:

- **`connect(userdata, host, port)`** — Establish the transport to `host:port`.
  Returns `0` on success, negative on failure. libsmb2 performs **no** name
  resolution and passes `host`/`port` to the callback verbatim; the application
  owns resolution. The callback is treated as **synchronous**: it must block until
  the transport is connected or fails (there is no async-connect-completion path
  on the external backend). The connection is considered established as soon as
  `connect` returns `0`.

- **`send(userdata, buf, len)`** — Send up to `len` bytes from `buf`. Returns the
  number of bytes sent (which may be **less than** `len` for a short write — the
  engine retries the remainder), or negative on error. A would-block condition
  should be reported the way the platform would for a non-blocking socket
  (negative return with `errno` set to `EAGAIN`/`EWOULDBLOCK`); libsmb2 preserves
  that `errno`. The callback **must not** return a value greater than `len`
  (libsmb2 rejects that as a protocol error).

- **`recv(userdata, buf, max_len)`** — Receive up to `max_len` bytes into `buf`.
  Returns the number of bytes received (`> 0`), `0` on peer close, or negative on
  error (with `errno` set; `EAGAIN`/`EWOULDBLOCK` is the normal "nothing yet"
  signal). The callback **must not** return more than `max_len` — libsmb2 rejects
  an over-long return (`errno = EIO`) so a buggy or hostile transport cannot push
  read data past the engine's buffer.

- **`close(userdata)`** — Tear the transport down. Returns `0` on success. A
  `NULL` `close` is treated as a successful no-op. The external backend owns no
  file descriptor and never calls `close()` on one; tearing down the underlying
  handle behind `userdata` is the application's job.

`smb2_set_transport()` copies the struct **by value**, so the application need not
keep the `struct smb2_external_transport` alive after the call. The lifetime of
`userdata` (and of whatever it points at) remains the application's
responsibility.

## 4. `smb2_set_transport()`

```c
int smb2_set_transport(struct smb2_context *smb2, int type,
                       const struct smb2_external_transport *ext);
```

Selects the transport for `smb2`. Returns `0` on success or a negative `errno`
value on invalid arguments (for example `SMB2_TRANSPORT_QUIC`/`AUTO` with a
half-populated `ext` — any of the four callbacks `NULL` is rejected, so a
partially filled `ext` can never reach the backend).

Ordering rules:

- Call `smb2_set_transport()` **before** `smb2_connect_share()` /
  `smb2_connect_share_async()` (and before any other connect entry point). On
  success the backend is bound immediately.
- Do **not** change the transport while a connection is established.
- Selecting `SMB2_TRANSPORT_TCP` drops any previously supplied external callbacks
  and restores the built-in TCP backend.

## 5. Timeout API

```c
int smb2_get_timeout(struct smb2_context *smb2, struct timeval *tv);
int smb2_service_timeout(struct smb2_context *smb2);
```

- **`smb2_get_timeout(smb2, tv)`** — Reports the next deadline at which the engine
  needs servicing, so an event loop can bound the timeout it passes to
  `poll()`/`select()`. Returns `1` when a deadline is pending — `*tv` is then the
  non-negative time remaining (`{0,0}` means "due now"); returns `0` when no timer
  is pending (`*tv` left unchanged); returns `<0` (`-EINVAL`) if `smb2` or `tv` is
  `NULL`. `*tv` is valid **only** when the return value is `1`.

- **`smb2_service_timeout(smb2)`** — Runs timer-driven processing. Call it
  whenever a deadline returned by `smb2_get_timeout()` has expired; calling it
  early is a safe no-op. For TCP this aborts any commands that have exceeded
  `smb2_set_timeout()` seconds with `SMB2_STATUS_IO_TIMEOUT`. For an external
  transport it additionally runs the backend timer hook. Returns `0` on success
  (including the nothing-was-due no-op case) or `-EINVAL` if `smb2` is `NULL`.

The timeout API is usable on the TCP path too (it bounds per-request timeouts);
it is **required** on the external path, where there is no pollable fd to wake the
loop, so timer-driven work would otherwise never be serviced.

## 6. Driving the session — minimal usage snippet

The external backend exposes no pollable file descriptor (`smb2_get_fd()` returns
`SMB2_INVALID_SOCKET`, `smb2_get_fds()` reports zero fds), so the loop cannot
block in `poll()` on the SMB session. Instead it bounds its wait with
`smb2_get_timeout()` and unconditionally services the engine each tick, calling
`smb2_service()` with the current event mask and draining timer work with
`smb2_service_timeout()`. The application's callbacks (notably `recv`) are what
the loop is really waiting on, and `recv` returning `EAGAIN`/`EWOULDBLOCK` is the
normal "nothing to do yet" signal.

This snippet uses **only** public symbols and **only** plain byte buffers; no
QUIC/TLS type appears anywhere, which doubles as the public-surface minimality
proof (§7).

```c
#include <smb2/libsmb2.h>
#include <smb2/smb2.h>

/* The application's transport. Here `my_conn` is whatever handle the
 * application's connect/send/recv/close need (a QUIC stream, a pipe, ...). */
struct my_conn;

static int my_connect(void *u, const char *host, int port);  /* 0 / <0      */
static int my_send(void *u, const uint8_t *buf, size_t len);  /* sent / <0   */
static int my_recv(void *u, uint8_t *buf, size_t max_len);    /* n / 0 / <0  */
static int my_close(void *u);                                 /* 0           */

int run(struct smb2_context *smb2, struct my_conn *conn,
        const char *server, const char *share, const char *user)
{
        struct smb2_external_transport ext;
        struct timeval tv;
        int err;

        /* 1. Plug in the four callbacks BEFORE connecting. */
        memset(&ext, 0, sizeof(ext));
        ext.userdata = conn;
        ext.connect  = my_connect;
        ext.send     = my_send;
        ext.recv     = my_recv;
        ext.close    = my_close;

        if (smb2_set_transport(smb2, SMB2_TRANSPORT_QUIC, &ext) < 0) {
                return -1;          /* invalid args / missing callback */
        }

        /* 2. Connect over the external transport. */
        if (smb2_connect_share(smb2, server, share, user) < 0) {
                return -1;
        }

        /* 3. Service loop. There is no SMB fd to poll, so bound the wait with
         *    smb2_get_timeout() and service every tick. */
        for (;;) {
                struct timeval wait = { 0, 50 * 1000 };   /* default 50 ms cap */

                if (smb2_get_timeout(smb2, &tv) == 1) {
                        /* Narrow (never widen) the wait to the next deadline. */
                        if (tv.tv_sec < wait.tv_sec ||
                            (tv.tv_sec == wait.tv_sec &&
                             tv.tv_usec < wait.tv_usec)) {
                                wait = tv;
                        }
                }

                /* Let the application's transport make progress / wait for
                 * readability. select() here polls the application's own
                 * handle, not an SMB fd; replace with the app's wait. */
                /* app_wait(conn, &wait); */

                /* Push pending writes and pull any available bytes. recv
                 * returning EAGAIN is fine -- nothing to read yet. */
                if (smb2_service(smb2, smb2_which_events(smb2)) < 0) {
                        break;      /* transport error / disconnect */
                }

                /* Run any expired timer-driven work (per-request timeouts,
                 * external-transport timers). Safe no-op if nothing is due. */
                smb2_service_timeout(smb2);

                /* ... application's own exit condition ... */
        }

        smb2_disconnect_share(smb2);
        return 0;
}
```

Key ordering: `smb2_set_transport()` is called **before** `smb2_connect_share()`;
the loop bounds its wait with `smb2_get_timeout()` and always drains with
`smb2_service()` + `smb2_service_timeout()`.

## 7. Public-surface minimality

The Stage-2 additions to `include/smb2/libsmb2.h` are, in full:

- three integer macros `SMB2_TRANSPORT_TCP` / `SMB2_TRANSPORT_QUIC` /
  `SMB2_TRANSPORT_AUTO`;
- `struct smb2_external_transport`, whose members are only `void *`,
  `const char *`, `int`, `uint8_t *`, and `size_t` — plain bytes and scalars;
- three function prototypes (`smb2_set_transport`, `smb2_get_timeout`,
  `smb2_service_timeout`) using only `struct smb2_context *`, `int`,
  `struct smb2_external_transport *`, and `struct timeval *`;
- one new system include, `<sys/time.h>` (for `struct timeval`).

No QUIC/TLS/ngtcp2/openssl type appears in the public header. This satisfies the
RandomPlayer#344 acceptance requirement that no QUIC library dependency is leaked
into the public API: an application links libsmb2 and supplies its own transport
without libsmb2 pulling in any QUIC stack.

## 8. Safety contract the application must honor

The external backend bounds-checks every untrusted value the application's
callbacks return before feeding the parser, but the application is responsible
for the following:

- `recv` returns **at most** `max_len` (over-long returns are rejected with
  `errno = EIO`), `> 0` for data, `0` only on genuine peer close, negative on
  error with `errno` set.
- `send` returns **at most** `len`; a short write is fine (the engine retries the
  remainder), an over-long return is rejected.
- The callbacks must tolerate being driven from `smb2_service()` even though there
  is no pollable fd; `EAGAIN`/`EWOULDBLOCK` from `recv`/`send` is the normal idle
  signal, not an error.
- `connect` must block until connected or failed; there is no async-connect path.
- `userdata` (and the transport handle behind it) is owned by the application;
  libsmb2 never closes a real descriptor on the external path.
