# Pluggable Transport Abstraction — Implementation Plan

> Fork-side breakdown of **simplekube-ro/RandomPlayer#344** — *"Fork and extend libsmb2 to allow swapping out the transport protocol."*
>
> This plan lives in the `simplekube-ro/libsmb2` fork. It decomposes the upstream
> design issue into four GitHub milestones and twenty PR-sized issues so the work
> can be implemented incrementally (by humans or AI agents) and curated into a
> clean, upstreamable PR series for `sahlberg/libsmb2`.

## Goal

Refactor libsmb2 so its transport layer (connect / send / recv / poll / close) is
**pluggable** instead of assuming it owns a POSIX TCP file descriptor. This is the
foundation for SMB-over-QUIC: SMB PDUs must be able to travel over a QUIC/UDP-443 +
TLS 1.3 tunnel (supplied by the application) instead of TCP/445. libsmb2 stays the
SMB engine; it stops owning the socket.

We follow **Route A** (make libsmb2 transport-pluggable), not Route B (use libsmb2
only as a PDU codec) and not a wholesale socket-backend-replacement fork.

**Out of scope here:** any QUIC library dependency *inside* libsmb2. The app supplies
the QUIC transport. An optional native C QUIC backend behind a build flag
(e.g. `--enable-quic=ngtcp2`) is possible *future* upstream work, not this series.

## Where the current code lives (map)

| Concern | Location |
| --- | --- |
| TCP transport (all of it) | `lib/socket.c` |
| Connect (Happy Eyeballs / RFC 8305) | `smb2_connect_async` — `lib/socket.c:1291` |
| Write path (`writev`) | `smb2_write_to_socket` — `lib/socket.c:225` (`writev` at `:292`) |
| Read path (`readv`) + state machine | `smb2_read_from_socket` `:886`, `smb2_read_data` `:340`, `smb2_readv_from_socket` `:878`, `smb2_readv_from_buf` `:918` |
| Service / poll | `smb2_service` `:1096`, `smb2_service_fd` `:961`, `smb2_which_events` `:187` |
| Socket state | `struct smb2_context` — `include/libsmb2-private.h:141+` (`fd`, `connecting_fds`, `outqueue`/`waitqueue`, `in`, `recv_state`, `events`, `timeout`) |
| Public transport API | `include/smb2/libsmb2.h` (`smb2_get_fd` `:193`, `smb2_get_fds` `:212`, `smb2_which_events` `:197`, `smb2_service` `:246`, `smb2_service_fd` `:263`, `smb2_set_timeout` `:273`, `smb2_connect_*` `:497+`) |
| Socket type abstraction | `t_socket` — `lib/compat.h` |
| Tests | `tests/` (shell `test_0*.sh` + C `prog_*.c`); no mock/loopback transport exists |
| Build | autotools (`configure.ac`, `*/Makefile.am`) **and** CMake (`CMakeLists.txt`) |

## Target internal interface

```c
struct smb2_transport_ops {
    int      (*connect)(struct smb2_context *smb2, const char *server,
                        smb2_command_cb cb, void *cb_data);
    int      (*service)(struct smb2_context *smb2, int revents);
    int      (*queue_write)(struct smb2_context *smb2, const uint8_t *buf, size_t len);
    int      (*close)(struct smb2_context *smb2);
    int      (*which_events)(struct smb2_context *smb2);
    t_socket (*get_fd)(struct smb2_context *smb2);
};
```

## Target public interface (Stage 2)

```c
struct smb2_external_transport {
    void *userdata;
    int (*connect)(void *userdata, const char *host, int port);
    int (*send)(void *userdata, const uint8_t *buf, size_t len);
    int (*recv)(void *userdata, uint8_t *buf, size_t max_len);
    int (*close)(void *userdata);
};

/* SMB2_TRANSPORT_TCP | SMB2_TRANSPORT_QUIC | SMB2_TRANSPORT_AUTO */
int smb2_set_transport(struct smb2_context *smb2, int type,
                       const struct smb2_external_transport *ext);

int smb2_get_timeout(struct smb2_context *smb2, struct timeval *tv);
int smb2_service_timeout(struct smb2_context *smb2);
```

## Milestones & issues

All issues are tracked in this repo. Each is sized for one agent → one PR.

### Milestone 1 — Stage 1: Internal transport abstraction *(no behavior change)*
- **#1** Define internal `smb2_transport_ops` interface + register TCP backend as default
- **#2** Route connection establishment through `transport->connect`
- **#3** Route poll surface (`get_fd` / `get_fds` / `which_events`) through the transport ops
- **#4** Route service / `service_fd` dispatch through `transport->service`
- **#5** Route byte-send + teardown through `queue_write`/`close`; isolate socket syscalls in the TCP backend
- **#6** Verification + internal docs — prove zero behavior change

### Milestone 2 — Stage 2: External transport callbacks & timer hooks
- **#7** Public API — `smb2_external_transport` + `SMB2_TRANSPORT_*` + `smb2_set_transport()`
- **#8** Implement the external-transport backend (app-supplied connect/send/recv/close)
- **#9** Wire `smb2_set_transport()` selection + integrate external backend into the service loop
- **#10** Add `smb2_get_timeout()` / `smb2_service_timeout()` + internal timer state
- **#11** Wire timer-driven processing into the engine + surface timeout via `smb2_get_fds`
- **#12** Verification + API docs for external transport & timeout API

### Milestone 3 — Mock transport & decoupling validation
- **#13** TCP-backed external-transport fixture (test owns the socket)
- **#14** Pure in-memory loopback transport + recorded-exchange fixture
- **#15** Full SMB exchange driven purely through external-transport callbacks
- **#16** Wire new transport sources & tests into autotools + CMake + GitHub Actions

### Milestone 4 — Upstream PR series (`sahlberg/libsmb2`)
- **#17** Curate Stage 1 into a clean PR for `sahlberg/libsmb2`
- **#18** Curate Stage 2 into a minimal PR for `sahlberg/libsmb2`
- **#19** Developer docs + `examples/` custom-transport sample
- **#20** Open PR(s) to `sahlberg/libsmb2` + track review feedback

## Dependency graph

```
#1 ─┬─> #2 ─┐
    ├─> #3 ─┤
    ├─> #4 ─┼─> #6 ─┬─> #7 -> #8 -> #9 ─┬─> #11 ─> #12 ─> #18 ─┐
    └─> #5 ─┘       │                   │                      │
                    └─> #10 ────────────┘                      │
                                                               │
   #9 ─┬─> #13 ─┐                                              │
       └─> #14 ─┴─> #15 ─> #16 ───────────────────────────────┤
                                                               │
   #6 ─> #17 ─────────────────────────────────────────────────┤
   #9 ─> #19 ─────────────────────────────────────────────────┤
                                                               ▼
                                                              #20  (open upstream PRs)
```

Stage 1 (#1–#6) is purely internal and must land first. Stage 2 (#7–#12) builds on it.
Validation (#13–#16) depends on the external backend being wired (#9). Upstreaming
(#17–#20) is the final convergence; #20 is the upstream tracking issue and is what
unblocks RandomPlayer **#345** and **#346**.

## Acceptance criteria (from RandomPlayer#344)

1. **All existing libsmb2 tests pass with TCP driven through the new abstraction — zero behavior change.** → gated by **#6**.
2. **A mock / in-memory transport drives a full SMB exchange purely through the external-transport callbacks (proves decoupling).** → delivered by **#13–#15**.
3. **Changes isolated as a clean PR series suitable for upstreaming.** → delivered by **#17–#20**.

## Notes / risks

- Maintainers may prefer a *small internal* abstraction over a *broad public* callback
  API — keep the public surface minimal and upstream-friendly (Stage 1 changes **no**
  public symbols; Stage 2 adds only the four functions/structs above).
- QUIC's timer needs are the reason for `smb2_get_timeout` / `smb2_service_timeout`;
  the `get_fd` + `service` (fd-readiness-only) model cannot express handshake / idle /
  loss-recovery timing.
- Effort estimate for the TCP-only abstraction (Stage 1 + Stage 2 callback surface):
  ~2–4 weeks.

---
*Source design conversation referenced in simplekube-ro/RandomPlayer#344.*
