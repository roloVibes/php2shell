# PHP2SHELL — reverse-engineering notes

How the PHP2SHELL exploit pair (CVE-2026-109618 / CVE-2026-109619) was
identified from the PHP **8.5.11 → 8.5.12** source diff, informed by the
published research (PHP advisories, Wiz Research, Calif, OpenAI, the
HackTheBox War Room analysis), and verified against both locally built
binaries. The raw diffs sit alongside this file:

- [diff_main.c](diffs/diff_main.c) — request-shutdown state reset (109619 fix)
- [diff_rfc1867.c](diffs/diff_rfc1867.c) — parser OOM handling (109618 fix)
- [diff_zend_alloc.c](diffs/diff_zend_alloc.c) — delayed-OOM machinery
- [diff_zend_globals.h](diffs/diff_zend_globals.h) — `EG(delayed_oom)` state

## The bug class

PHP's `rfc1867` multipart POST parser runs **before any userland PHP code**,
in the same process as the request. That gives it two dangerous properties:

1. It allocates with the request memory limit in force, and
2. It writes into **process-global** state that outlives the request.

The published research groups four exploitable instances under the two CVEs:

| CVE | Instance | Mechanism (per Wiz) |
|---|---|---|
| 109618 | Upload-progress unserializer UAF | the session decoder's `BG(unserialize)` bookkeeping is left published after a fatal; a later request consumes attacker-reclaimed memory as live bookkeeping |
| 109618 | Remote process-memory disclosure | session upload-progress publishes `PS(id)` into request memory during parsing; an OOM leaves it dangling, and a later multipart request URL-encodes the reclaimed heap into a `PHPSESSID` Set-Cookie — application-agnostic, works without `session_start()` |
| 109619 | Fatal-error backtrace UAF | `EG(last_fatal_error_backtrace)` survives the request-heap destruction; an early diagnostic in the next request follows the dangling pointer (RCE demonstrated on Drupal; PHP 8.5-specific producer, mitigated by `fatal_error_backtraces=0`) |
| 109619 | OPcache type confusion | `zend_accel_script_persist()` advances the process-local `CG(map_ptr_last)` frontier before publishing the shared frontier; an allocation failure in between leaves partially persisted objects on slots another worker can reuse — cross-worker type confusion (RCE demonstrated on WordPress) |

Calif's writeup adds the core 109618 primitive this repo reproduces: a
**HashTable count-then-key-alloc-fail** — the live-entry count is
incremented, the key allocation fails, and cleanup processes the unfinished
entry as though it were valid.

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
each marker is present in 8.5.12 and provably absent from 8.5.11.

## The triggers (all measured in this lab)

**Trigger 1 — one oversized text field.** With
`memory_limit=4M post_max_size=64M upload_max_filesize=1K`, a 16 MB text
field trips the parser's body-buffer allocation on both builds: 8.5.11 dies
at `main/rfc1867.c:632`, 8.5.12 at `main/rfc1867.c:665`. File parts do NOT
trigger it — they stream to disk and bypass the in-memory buffer path.

**Trigger 2 — nested empty file fields (amplification).** Per the HTB/Calif
analysis, "nested empty file fields cause PHP to build several metadata
trees." Measured: with `max_file_uploads` lifted, **2500 parts (a 0.29 MB
body) exhaust a 4M limit** — ~18× heap amplification — and the fatal lands
in `zend_hash.c` (the count-then-key-alloc-fail primitive), e.g.
`zend_hash.c:290`. PHP's **default `max_file_uploads=20` blocks this
entirely** (verified: no OOM at any part count with the default cap) — that
default is itself one of the documented edge mitigations. Nested *text*
field names do not amplify enough to matter on default configs (no OOM at
80k parts / 5.5 MB body against a 4M limit).

**Trigger 3 — the session-state chain (109619).** A `PHP_SESSION_UPLOAD_PROGRESS`
field placed first in the multipart stream makes the session module
initialize early and publish `PS(id)` (from the request's `PHPSESSID`
cookie) into request memory. Chain, measured 4/4 deterministic on 8.5.11:

1. POST the Trigger-2 body with a `PHPSESSID` cookie → OOM at
   `zend_hash.c:290`, request aborts, `PS(id)` left dangling.
2. POST a small multipart that *also* carries `PHP_SESSION_UPLOAD_PROGRESS`
   → the upload-progress path is reached before normal Session init resets
   the pointer → **the worker dies** (segfault / abort trap in a debug
   build).

Controls that isolate the mechanism (all measured):
- **no cookie** → OOM lands at `zend_hash.c:176` instead, follow-up
  survives (PS(id) was never published);
- **text-field OOM instead of HashTable OOM** (`rfc1867.c:632`) → follow-up
  survives (the crash is specific to the HashTable allocation path);
- **fixed 8.5.12** → same OOM site family (`zend_hash.c:244`), deferred,
  every follow-up answered 200 OK.

## The display_errors discriminator

Measured on both builds, both settings:

| | display_errors=1 | display_errors=0 |
|---|---|---|
| **8.5.11** | fatal text in body: `Allowed memory size ... exhausted at .../main/rfc1867.c:632` | HTTP 500, 0-byte body |
| **8.5.12** | fatal text in body: `... rfc1867.c:665` | HTTP 500, 0-byte body |

With `display_errors=0` — the realistic default — the crash alone cannot
distinguish pre-fix from fixed. The `.c:NNN` site and the version string
carry the verdict; a crash alone only says "the request path died", which is
why the scanner's crash-only verdict tops out at `LIKELY VULNERABLE`. Note
also that fatal sites are heap-state dependent (`zend_hash.c:176/244/290/326`
were all observed) — key on the file, not the line.

A second caveat from the advisories: **a version banner cannot prove a
distro backport.** The scanner states this on every version-based
`NOT VULNERABLE` verdict.

## Honest negatives

- **The PHPSESSID memory-disclosure form did not reproduce** on the
  single-process dev server — follow-up responses carry fresh,
  normal-length session IDs (the corruption *crash* reproduces 4/4). The
  scanner still checks for the anomalous-cookie signature, since it is the
  published detection signal for the disclosure path.
- **The 109619 cross-request leak via plain `$_POST` is not observable** on
  the dev server — the fix is verified at source level (R3).
- **The exit-121 CGI mapping needs `ZEND_MM_MAX_ALLOCS`**, custom-heap
  (test) builds only; in an NTS build the plain OOM exits 255 on both
  versions. Measured, not elided.

## Deployment risk ranking (from the advisories)

All web SAPIs are in scope — PHP-FPM, Apache mod_php, php-cgi, FrankenPHP,
LiteSpeed. **mod_php is the highest risk**: the confirmed 109618 path fires
during automatic input parsing and reaches unsafe cleanup before the target
script runs — no authentication, no application code required. The FPM
session path (109619) needs a suitable application operation interrupted
after request startup. Every deployment still needs the update.

## Disclosure timeline (from Wiz)

- 2026-08-19 — Wiz discovers the first vulnerability (using Wiz Atlas,
  Gemini 4 Argon, GPT-5.6 Sol — the "AI inflection point" in their writeup)
- 2026-08-20/21 — unauthenticated RCE confirmed against Drupal, then WordPress
- 2026-08-24 — reported to the PHP security team
- 2026-10-21 — patched releases (8.5.12 / 8.4.27 / 8.3.36 / 8.2.35) + public disclosure
- 2026-10-21+ — active probing observed (Patchstack, Cloudflare, AWS MadPot
  honeypots saw attempts from 2026-10-17); Unit 42 estimates 22.6M exposed
  instances; no verified real-world compromise documented as of 2026-10-26

## Lab reproduction

Build both trees with the session module (the original `--disable-all`
builds lack it — that hid the session-state path from the first research
pass), then point the PoC at them:

```sh
mkdir -p ~/php2shell-lab && cd ~/php2shell-lab
# unpack php-8.5.11 and php-8.5.12 sources, then in each:
./configure --disable-all --enable-cli --enable-cgi --enable-session --enable-debug && make -j

export PHP2SHELL_LAB=~/php2shell-lab
python3 poc/php2shell_poc.py        # exit 0 = every assertion held
```

To drive the scanner against your own lab server instead of a remote host:

```sh
~/php2shell-lab/php-8.5.11/sapi/cli/php -S 127.0.0.1:8711 \
    -d memory_limit=4M -d post_max_size=64M -d upload_max_filesize=1K \
    -d max_file_uploads=100000 -d display_errors=1 -t poc &
./php2shell.py http://127.0.0.1:8711/t.php --yes-i-own-or-authorized
```

The verification matrix for all build × display_errors × max_file_uploads
combinations is in [../evidence/](../evidence/).
