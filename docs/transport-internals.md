# Internal Transport Abstraction — Ops Table & Stage-1 Sign-off

> Companion to `docs/transport-abstraction-plan.md`. This document is the Stage-1
> gate deliverable for **simplekube-ro/libsmb2#6**: it proves the internal
> transport abstraction is **complete** and **invisible** (zero behavior change
> for TCP) and documents the `smb2_transport_ops` table for contributors.

## 1. What the abstraction is

The SMB engine no longer assumes it owns a POSIX TCP file descriptor. All
connect / service / send / poll / close operations are routed through a function
table, `struct smb2_transport_ops` (declared in `lib/smb2-transport.h`). Every
context created by `smb2_init_context()` is bound to the default TCP backend:

```c
/* lib/init.c */
smb2->transport = &smb2_tcp_transport_ops;
```

The table literal `smb2_tcp_transport_ops` and all `tcp_*` implementations live
in `lib/socket.c`. The `transport` field is on `struct smb2_context`
(`include/libsmb2-private.h`). Stage 1 exposes **no public API** to change the
binding — `include/smb2/libsmb2.h` is byte-identical to its pre-Stage-1 state —
so for every existing caller `smb2->transport->op()` resolves to exactly the
`tcp_*` function that used to be the inline implementation.

## 2. Ops table — entry point → TCP backend → routing issue

The table has **seven** members. (The issue text speaks of "six operations"; the
poll surface is split into `which_events` + `get_fd` + `get_fds`, so `get_fds`
is listed alongside `get_fd`.)

| Op (`smb2_transport_ops` field) | Public / engine entry point → dispatch | TCP backend impl | Routed by |
| --- | --- | --- | --- |
| `connect`      | `smb2_connect_async` → `smb2->transport->connect` | `tcp_connect` | #2 |
| `which_events` | `smb2_which_events` → `transport->which_events`   | `tcp_which_events` | #3 |
| `get_fd`       | `smb2_get_fd` → `transport->get_fd`               | `tcp_get_fd` | #3 |
| `get_fds`      | `smb2_get_fds` → `transport->get_fds`             | `tcp_get_fds` | #3 |
| `service`      | `smb2_service_fd` → `transport->service`; `smb2_service` → `smb2_service_fd` | `tcp_service` | #4 |
| `queue_write`  | `smb2_write_to_socket` → `transport->queue_write` | `tcp_queue_write` | #5 |
| `close`        | `smb2_destroy_context` (init.c), free/disconnect paths (libsmb2.c) → `transport->close` | `tcp_close` | #5 |

Registration: `smb2_init_context()` in `lib/init.c`.

### NULL-op contract (for future external backends)

Every dispatcher guards `smb2->transport == NULL || transport->op == NULL` and
returns a documented value, so a Stage-2 backend that leaves an op unset fails
predictably (this can never happen for TCP, where all seven are set):

| Op | Return when op missing |
| --- | --- |
| `connect`      | `-EINVAL` |
| `service`      | `-1` |
| `queue_write`  | `-1` |
| `which_events` | `0` (no events) |
| `get_fd`       | `-1` |
| `get_fds`      | `NULL`, `*fd_count = 0`, `*timeout = -1` |
| `close`        | guarded; no-op |

## 3. Sign-off checklist — every operation routed through `transport->*`

- [x] **connect** — `smb2_connect_async` dispatches via `transport->connect` (#2).
- [x] **which_events** — `smb2_which_events` dispatches via `transport->which_events` (#3).
- [x] **get_fd** — `smb2_get_fd` dispatches via `transport->get_fd` (#3).
- [x] **get_fds** — `smb2_get_fds` dispatches via `transport->get_fds` (#3).
- [x] **service** — `smb2_service_fd` dispatches via `transport->service`; `smb2_service` delegates to `smb2_service_fd` (#4).
- [x] **queue_write** — `smb2_write_to_socket` reaches the wire only via `transport->queue_write` (#5).
- [x] **close** — `smb2_destroy_context` and the `libsmb2.c` free/disconnect paths dispatch via `transport->close` (#5).
- [x] No public symbol added or changed (`include/smb2/libsmb2.h` unchanged).

## 4. Static sweep — raw socket I/O is isolated to the TCP backend

Raw client-transport syscalls (`connect` / `writev` / `readv` / `getsockopt` /
`setsockopt` / `socket` / `close`) appear in the SMB engine only in:

- `lib/socket.c` — the TCP backend itself (`tcp_*` functions); and
- `lib/compat.h` / `lib/compat.c` — platform shims (Win32/Amiga/ESP/etc.) that
  *implement* `writev`/`readv`/`poll`/`getsockopt`/`closesocket`. These
  legitimately sit outside the abstraction because they are the portability
  layer the backend is built on.

### Intentional remaining `smb2->fd` references (NOT leakage)

`smb2->fd` is still the canonical "am I connected" state for the TCP backend.
These references are connectedness predicates (`SMB2_VALID_SOCKET`) or
event-loop hints, not raw I/O, and are deliberately left for Stage 2 (an
external transport has no fd):

| Location | Reference | Why it stays |
| --- | --- | --- |
| `lib/init.c:287` | `smb2->fd = SMB2_INVALID_SOCKET` | Field initialization. |
| `lib/pdu.c:583` | `smb2_change_events(smb2, smb2->fd, smb2_which_events(smb2))` | fd is an identifier handed to the app's change-events callback. |
| `lib/sync.c:83,861,961` | `SMB2_VALID_SOCKET(smb2->fd)` | "Still connected?" guards in the synchronous wrappers. |
| `lib/libsmb2.c:2688` | `SMB2_VALID_SOCKET(smb2->fd)` | Connectedness check. |
| `lib/libsmb2.c:4086` | `smb2->fd = fd` | Server-side / sync-connect completion. |
| `lib/libsmb2.c:4203` | `SMB2_VALID_SOCKET(smb2->fd)` server-timeout | Connectedness check. |

### Server listening socket — a separate concern

`lib/libsmb2.c:4139–4276` use `server->fd` (the listening socket) and the lone
`close(server->fd)` at 4275. This is the server-side accept loop, distinct from
the client transport fd, and is intentionally not abstracted in Stage 1.

### Application-side poll

`lib/sync.c:73` already uses the abstracted `smb2_get_fd(smb2)`, while
`lib/sync.c:76` calls `poll()` directly. That `poll()` is the **application-side**
synchronous event loop (the app is allowed to drive its own poll); it is not
engine-internal transport I/O.

## 5. Zero-behavior-change argument (TCP)

The argument is structural:

- **Unconditional, identical binding.** Every context gets
  `smb2->transport = &smb2_tcp_transport_ops`, and no Stage-1 API can replace it.
- **Pure pass-through dispatchers.** Each entry point forwards its arguments
  unchanged to the `tcp_*` function that is the verbatim former inline body. The
  only inserted code is a NULL-guard that triggers only on a NULL transport/op —
  impossible for a TCP context — so the happy path is byte-for-byte unchanged.
- **Hot path untouched.** `tcp_service` still calls the concrete helpers
  (`smb2_read_from_socket`, `smb2_write_to_socket`, `smb2_change_events`,
  `smb2_which_events`) directly. `tcp_queue_write` is a bare `writev` that leaves
  `errno` intact for the caller's `EAGAIN`/`EWOULDBLOCK` check; the `readv` read
  path is unchanged. POLLOUT gating by outqueue/credits and the
  `SPL→HEADER→FIXED→VARIABLE→PAD` (+ `TRFM`) recv state machine are unmodified.
- **`close` portability preserved.** `tcp_close` uses `close()`, which `compat.h`
  maps to `closesocket()` on Win32 — unchanged from before.

## 6. Build / test evidence

Both build systems compile `lib/socket.c` and `lib/init.c` cleanly with the
Stage-1 abstraction in place, on the `issue-6-verification-docs` branch:

- **CMake:** `cmake -S . -B .wf-build -DENABLE_LIBKRB5=OFF -DENABLE_GSSAPI=OFF -DENABLE_EXAMPLES=OFF && cmake --build .wf-build` → exit 0; `libsmb2` target built (`socket.c.o`, `init.c.o` produced).
- **Autotools:** `./bootstrap && ./configure --without-libkrb5 && make` → exit 0; `libsmb2.la` linked (`-Werror` clean).

The Stage-1 changes that land in this issue are documentation-only (this file, an
expanded header comment in `lib/smb2-transport.h`, and a corrected backend
comment in `lib/socket.c`); they add no `.c`/`.h` source and change no public
symbol, which is itself part of the proof.
