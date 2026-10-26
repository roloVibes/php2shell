# PHP2SHELL — reverse-engineering notes

How the PHP2SHELL exploit pair (CVE-2026-109618 / CVE-2026-109619) was
identified from the PHP **8.5.11 → 8.5.12** source diff and verified against
both builds. The raw diffs this is all built from sit alongside this file:

- [diff_main.c](diffs/diff_main.c) — request-shutdown state reset (109619 fix)
- [diff_rfc1867.c](diffs/diff_rfc1867.c) — parser OOM handling (109618 fix)
- [diff_zend_alloc.c](diffs/diff_zend_alloc.c) — delayed-OOM machinery
- [diff_zend_globals.h](diffs/diff_zend_globals.h) — `EG(delayed_oom)` state

## The bug class

PHP's `rfc1867` multipart POST parser runs **before any userland PHP code**,
in the same process as the request. That gives it two dangerous properties:

1. It allocates the body buffer with the request memory limit in force, and
2. It writes into **process-global** state that outlives the request.

PHP2SHELL is the composition of both:

- **CVE-2026-109618** — when the parser hits `memory_limit` mid-parse, the
  vulnerable engine does `zend_mm_safe_error()` → `zend_error_noreturn(E_ERROR)`
  → `zend_bailout()` — a `longjmp` out of the parser with **no OOM state
  recorded anywhere** (`grep -r ZEND_HAS_OOM php-8.5.11/Zend/` → 0 hits).
  Request memory is left uninitialized and the engine keeps running on
  stale state.
- **CVE-2026-109619** — `PG(http_globals)` (the `$_POST`/`$_GET`/… zvals)
  and `EG(delayed_oom)` temporarily point into request memory. On
  8.5.11, `php_request_shutdown()` dtors those zvals but does **not**
  `ZVAL_UNDEF` the slots (main.c:2016) — the next request can read freed
  state through them.

## What 8.5.12 changed

The fix is a coordinated mechanism across four files:

| Mechanism | Where | Effect |
|---|---|---|
| `EG(delayed_oom)` state machine | `zend_globals.h`, `zend_alloc.c:409` | OOM is recorded, not acted on mid-parse |
| `zend_handle_delayed_oom()` | `zend_vm_def.h:10549`, `main.c` | the recorded OOM fires later, at a **safe point** |
| `ZEND_HAS_OOM()` | `zend_alloc.h:63` | 20 checks threaded through `rfc1867.c` alone |
| `ZVAL_UNDEF(&PG(http_globals)[i])` | `main.c:2058` (shutdown) | kills the dangling global slots (109619) |
| `EG(delayed_oom).state = ZEND_OOM_STATE_NONE` | `main.c` shutdown | resets the OOM state between requests |
| `PG(modules_activated) = 0` | `main.c:2118` | NEW — prevents stale module activation state |
| `memory_hard_limit_percent` INI | `main.c` | a hard ceiling above `memory_limit` |
| `_exit(137)` hard-limit abort | `zend_alloc.c:519` | when the hard limit is hit, die immediately |

On 8.5.12 the parser OOM is therefore **deferred and recovered**; on 8.5.11
it is an immediate fatal with unrecorded state. The PoC's R3 check verifies
each of these markers is present in 8.5.12 and provably absent from 8.5.11 —
this is what makes the two builds distinguishable.

## The trigger (measured)

One oversized **text** multipart field. With
`memory_limit=4M post_max_size=64M upload_max_filesize=1K`, a 16 MB text
field trips the parser's body-buffer allocation on both builds:

- 8.5.11 dies at `main/rfc1867.c:632`
- 8.5.12 dies at `main/rfc1867.c:665`

**File parts do not trigger it** — they stream to disk and bypass the
in-memory buffer path entirely. That asymmetry is the scanner's core trick:
it never uploads a file, it POSTs a giant text field.

## The display_errors discriminator

Measured on both builds, both settings:

| | display_errors=1 | display_errors=0 |
|---|---|---|
| **8.5.11** | fatal text in body: `Allowed memory size of 4194304 bytes exhausted at .../main/rfc1867.c:632` | HTTP 500, 0-byte body |
| **8.5.12** | fatal text in body: `... rfc1867.c:665` | HTTP 500, 0-byte body |

With `display_errors=0` — the realistic default — the crash alone cannot
distinguish pre-fix from fixed. The `.c:NNN` site (visible only with
`display_errors=1`) and the reported version string carry the verdict; the
crash alone only says "the request path died", which is why the scanner's
crash-only verdict tops out at `LIKELY VULNERABLE`.

## Honest negatives

- **The 109619 cross-request leak is not observable on a single-worker PHP
  dev server** — the built-in server tears the request down either way. The
  fix is verified at the source level (R3) instead, which is where it lives.
- **The exit-121 CGI mapping needs `ZEND_MM_MAX_ALLOCS`**, which exists only
  in custom-heap (test) builds. In an NTS build the plain `memory_limit` OOM
  exits 255 on both versions. Measured, not elided.

## Lab reproduction

Build both trees, then point the PoC at them:

```sh
mkdir -p ~/php2shell-lab && cd ~/php2shell-lab
# unpack php-8.5.11 and php-8.5.12 sources, then in each:
./configure --disable-all --enable-cli --enable-cgi && make -j

export PHP2SHELL_LAB=~/php2shell-lab
python3 poc/php2shell_poc.py        # exit 0 = every assertion held
```

To drive the scanner against your own lab server instead of a remote host:

```sh
~/php2shell-lab/php-8.5.11/sapi/cli/php -S 127.0.0.1:8711 \
    -d memory_limit=4M -d post_max_size=64M -d upload_max_filesize=1K \
    -d display_errors=1 -t poc &
python3 scanner/php2shell_scanner.py http://127.0.0.1:8711/t.php \
    --yes-i-own-or-authorized
```

The verification matrix for all four build × display_errors combinations is
in [../evidence/](../evidence/).
