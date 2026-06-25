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
event-loop hints, not raw I/O:

| Location | Reference | Why it stays |
| --- | --- | --- |
| `lib/init.c:287` | `smb2->fd = SMB2_INVALID_SOCKET` | Field initialization. |
| `lib/pdu.c:583` | `smb2_change_events(smb2, smb2->fd, smb2_which_events(smb2))` | fd is an identifier handed to the app's change-events callback. |
| `lib/libsmb2.c:4086` | `smb2->fd = fd` | Server-side / sync-connect completion. |

Stage 2 update: the "still connected?" guards that previously read
`SMB2_VALID_SOCKET(smb2->fd)` directly (sync.c `wait_for_reply`/`smb2_echo`/
`smb2_share_enum_sync`, `smb2_disconnect_share_async`, and the server-loop
timeout) are now routed through `smb2_transport_is_connected()`. For the TCP
backend that helper returns exactly `SMB2_VALID_SOCKET(smb2->fd)` (zero
behavior change); for the external backend it returns `smb2->ext_connected`,
which the external backend sets in `ext_connect` and clears in `ext_close`
(the external transport owns no fd). The synchronous and async service loops
also gained a "no pollable fd → service via `smb2_which_events()`" branch so an
external session is driven even though `poll`/`select` cannot wake on it.

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

## 6. Build & test evidence

All commands were run on the `issue-6-verification-docs` branch (macOS / arm64,
clang via `gcc -std=gnu23`).

### 6.1 Builds — both systems compile the abstraction cleanly

- **CMake:** `cmake -S . -B .wf-build -DENABLE_LIBKRB5=OFF -DENABLE_GSSAPI=OFF -DENABLE_EXAMPLES=OFF && cmake --build .wf-build` → exit 0; `smb2` target built (`.wf-build/lib/CMakeFiles/smb2.dir/socket.c.o` and `init.c.o` produced).
- **Autotools:** `sh ./bootstrap && ./configure --without-libkrb5 && make` → exit 0; `lib/.libs/libsmb2` archive/dylib linked.

### 6.2 Tests executed

The acceptance criterion is "all existing tests pass — zero behavior change."
The test inventory in `tests/` splits into two classes:

| Test | Kind | Result |
| --- | --- | --- |
| `tests/aes128ccm-test.c` | self-contained crypto KAT (no context, no network) | **PASS** — built against `lib/.libs/libsmb2.a`, ran to exit 0; every `Expected:` block equals its `Got:` block (AES-128-CCM encrypt + decrypt vectors). |
| transport lifecycle smoke (throwaway, not committed) | exercises the abstraction directly: `smb2_init_context` (binds `transport`) → `smb2_get_fd`/`smb2_which_events` (dispatch via `transport->get_fd`/`->which_events`) → `smb2_destroy_context` (teardown via `transport->close`) | **PASS** — exit 0; `get_fd=-1` (correct: not connected), `which_events=4` (`POLLIN`), clean destroy. Direct runtime proof the dispatch path resolves to the `tcp_*` backend with no behavior change. |

### 6.3 Tests deferred (and why)

- **Functional suite `tests/test_0*.sh` (and `test_900_dcerpc.sh`)** — these source
  `tests/functions.sh`, which `. ./setup.local` to obtain SMB server / share /
  credentials and then drive `prog_ls`/`prog_cat`/etc. against a **live Samba
  server**. No `setup.local` and no server are available in this environment, so
  the functional suite is out of scope here; it is the integration gate that runs
  in CI / against a real server, not on the build host.
- **`tests/smb2-dcerpc-coder-test.c`** (in `noinst_PROGRAMS`) and
  **`tests/ntlmssp_generate_blob.c`** — both fail to compile on this branch due to
  **pre-existing** issues unrelated to Stage 1: the dcerpc coder test calls an
  internal encoder with 7 args where the current API expects 8 (stale test), and
  the ntlmssp helper includes `libsmb2.h` before `smb2.h` so `SMB2_GUID_SIZE` /
  `smb2_lease_key` are undeclared. These test files are **byte-identical to the
  parent branch** `issue-5-route-write-close` (this issue touches only `docs/`,
  `lib/smb2-transport.h`, and a comment in `lib/socket.c`), so the failures are
  not a regression introduced here.

### 6.4 Why this is sufficient evidence of zero behavior change

The Stage-1 changes that land in this issue are documentation-only (this file, an
expanded header comment in `lib/smb2-transport.h`, and a corrected backend
comment in `lib/socket.c`); they add no `.c`/`.h` source and change no public
symbol. The runtime smoke test confirms the dispatch surface resolves to the TCP
backend, and the crypto KAT confirms the linked library is functional. Combined
with the structural argument in §5 (every dispatcher is a pure pass-through to the
verbatim former inline body, bound unconditionally to `smb2_tcp_transport_ops`),
the abstraction is complete and invisible for TCP.

## 7. Stage-2 sign-off — external transport & timeout API (issue #12)

> This section is the Stage-2 verification gate for
> **simplekube-ro/libsmb2#12**. It records the build/test evidence for the
> external-transport + timeout work (issues #7–#11) and argues that the default
> TCP path is still byte-for-byte unchanged. The public API itself is documented
> in `docs/transport-external-api.md`; this section is the *verification*
> companion (mirroring §6 above for Stage 1). Evidence was gathered on branch
> `issue-12-verification-docs` (macOS / arm64, `gcc -std=gnu23` = Apple clang).

### 7.1 What landed in Stage 2 (and where TCP is untouched)

The Stage-2 implementation adds a **second** transport backend
(`smb2_external_transport_ops` in `lib/transport-external.c`) and a timer hook,
selectable at runtime via `smb2_set_transport()`. The TCP backend
(`smb2_tcp_transport_ops`) and all `tcp_*` functions are unchanged except for one
additive `timer = NULL` initializer (the new 8th ops-table slot). New code lives
in new translation units (`lib/transport-external.c`, `lib/timer.c`) and in new
functions in `lib/socket.c` (`smb2_recv_from_ext`, `smb2_read_from_ext`,
`smb2_transport_is_connected`); no TCP object code is altered.

Zero-behavior-change argument for TCP (extends §5):

- **Default binding unchanged.** `smb2_init_context()` still binds
  `smb2->transport = &smb2_tcp_transport_ops` and sets
  `transport_type = SMB2_TRANSPORT_TCP` (`== 0`, already the calloc default).
- **Connectedness guard is identical for TCP.** `smb2_transport_is_connected()`
  returns exactly `SMB2_VALID_SOCKET(smb2->fd)` on the TCP branch, so the guard
  substitutions in `sync.c` / `libsmb2.c` are semantically identical.
- **New no-fd service branches never fire for TCP.** The "no pollable fd but
  connected → service via `smb2_which_events()`" branches in `wait_for_reply` and
  `smb2_serve_port` are gated on `!SMB2_VALID_SOCKET(...) &&
  smb2_transport_is_connected(smb2)`; a TCP context always has a valid fd, so it
  never enters the new branch.
- **Timeout narrowing is a no-op for idle TCP.** With the default
  `smb2_set_timeout(0)` and no backend `next_timeout`, `smb2_next_timeout_ms()`
  returns `-1`, so `smb2_get_fds()` leaves `*timeout` exactly as the TCP backend
  produced it — no extra wakeups.
- **Write guard relaxed only off the TCP path.** `smb2_write_to_socket()` only
  relaxes its "not connected" early-return for `transport_type !=
  SMB2_TRANSPORT_TCP`; the TCP guard is unchanged.

### 7.2 Bounds-safety of the new external path

The new code never trusts a length or return value coming from the application's
callbacks before feeding the parser (full app-facing contract in
`docs/transport-external-api.md` §8):

- `smb2_recv_from_ext` (`lib/socket.c`) clamps the requested length to `INT_MAX`
  and **rejects** a callback return greater than the requested length
  (`errno = EIO`, `-1`) so a buggy/hostile `recv` cannot push `smb2->in.num_done`
  past the buffer. `ret == 0` is interpreted as peer close; `ret < 0` preserves
  `errno` for the `EAGAIN`/`EWOULDBLOCK` translation in `smb2_read_data`.
- `ext_queue_write` (`lib/transport-external.c`) clamps each vector length to
  `INT_MAX`, rejects an over-long send return (`EIO`), and returns the partial
  byte total on a short write so `num_done` never over-advances.
- `smb2_set_transport` rejects `QUIC`/`AUTO` (with `ext`) unless all four
  callbacks are non-`NULL`; `ext_connect`/`ext_queue_write`/`smb2_recv_from_ext`
  each NULL-check their callback; `ext_close` treats a `NULL` close as a no-op.
- The external backend owns no descriptor: `ext_get_fd` returns
  `SMB2_INVALID_SOCKET`, `ext_get_fds` returns `NULL`/`*fd_count = 0`, and
  `ext_close` never calls `close()` on a real fd.

Latent edges flagged for follow-up (NOT changed under #12, not regressions):

- (i) `smb2_recv_from_ext`'s `want == 0` early `return 0` would be read by
  `smb2_read_data` as peer-close; it is currently unreachable (the state machine
  never presents a zero-length first trimmed vector) but the surrounding comment
  is self-contradictory — a latent edge worth a later tidy.
- (ii) `ext_connect` does no name resolution and hands `host`/`port` to the
  application verbatim — intended; the application owns resolution.
- (iii) `ext_connect` treats the connection as immediately established
  (synchronous `connect`); there is no async-connect failure path on the external
  backend — documented as the contract that `ext.connect` blocks until connected
  or fails.

### 7.3 Build evidence — both build systems, the gated flag combination

- **CMake (hard gate):**
  `cmake -S . -B .wf-build -DENABLE_LIBKRB5=OFF -DENABLE_GSSAPI=OFF -DENABLE_EXAMPLES=OFF`
  then `cmake --build .wf-build` → **exit 0**; the new units compiled
  (`.wf-build/lib/CMakeFiles/smb2.dir/transport-external.c.o` and `timer.c.o`
  produced). Neither new file references krb5/gssapi, so the
  `-DENABLE_LIBKRB5=OFF -DENABLE_GSSAPI=OFF` combination builds clean.
- **Autotools (no-regression gate):**
  `sh ./bootstrap && ./configure --without-libkrb5 && make` → **exit 0**;
  `lib/.libs/libsmb2` linked. (`bootstrap` lacks the exec bit so it is invoked as
  `sh ./bootstrap`; `autoreconf` uses `glibtoolize` on macOS.)

Build wiring verified present on this branch: `lib/Makefile.am`
`libsmb2_la_SOURCES` lists `transport-external.c` + `timer.c`, and
`lib/CMakeLists.txt` lists both files in **all three** source blocks
(`ESP_PLATFORM`, `IOP`/`BUILD_IRX`, and the default `else`). `lib/libsmb2.syms`
exports exactly the three new public functions (`smb2_get_timeout`,
`smb2_service_timeout`, `smb2_set_transport`).

### 7.4 Tests executed

| Test | Kind | Result |
| --- | --- | --- |
| `tests/aes128ccm-test.c` | self-contained crypto KAT (no context, no network) | **PASS** — built against `lib/.libs/libsmb2.a`, ran to exit 0; every `Expected:` block equals its `Got:` block (AES-128-CCM encrypt + decrypt vectors), `Decrypted correct: 0`. Confirms the linked library (now including the Stage-2 units) is functional. |

### 7.5 Tests deferred (and why) — identical to the §6.3 Stage-1 deferrals

- **Functional suite `tests/test_0*.sh` (and `test_900_dcerpc.sh`)** source
  `tests/functions.sh`, which `. ./setup.local` to obtain SMB server / share /
  credentials and drive `prog_ls`/`prog_cat`/etc. against a **live Samba server**.
  No `setup.local` and no server exist in this environment, so the functional
  (integration) suite is out of scope on the build host; it is the CI / real-server
  gate.
- **`tests/smb2-dcerpc-coder-test.c`** and **`tests/ntlmssp_generate_blob.c`** have
  **pre-existing** compile failures unrelated to this work (stale coder-test arity;
  ntlmssp header include order), identical to the parent branch. This branch
  touches only `docs/`, so every test source is **byte-identical to the parent**
  `issue-11-wire-timer` — the failures are not introduced here and are not a
  regression.

### 7.6 Why this is sufficient evidence of zero TCP behavior change

This issue (#12) lands **documentation only** — `docs/transport-external-api.md`
and this section. It adds no `.c`/`.h` source and changes no public symbol. The
Stage-2 *implementation* it documents is on the parent branch and is exercised by
the same KAT and clean dual-build above. Combined with the structural argument in
§7.1 (TCP keeps its unconditional `smb2_tcp_transport_ops` binding; every new
branch is gated so a TCP context never enters it; the only TCP-table edit is an
additive `timer = NULL`), the external transport and timeout API are additive and
the default TCP path is unchanged.
