<p align="center">
  <img alt="PHP2SHELL" src="https://img.shields.io/badge/PHP2SHELL-CVE--2026--109618%20%2B%20CVE--2026--109619-5b4bd6?style=for-the-badge">
</p>

<p align="center">
  <a href="#run-it"><img alt="version 1.1" src="https://img.shields.io/badge/version-1.1-5b4bd6"></a>
  <img alt="python 3.7+" src="https://img.shields.io/badge/python-3.7%2B-3776ab">
  <img alt="stdlib only" src="https://img.shields.io/badge/dependencies-0-2e8b57">
  <img alt="Linux, macOS" src="https://img.shields.io/badge/platform-Linux%20%7C%20macOS-2b2b2b">
  <a href="LICENSE"><img alt="license" src="https://img.shields.io/badge/license-all%20rights%20reserved-lightgrey"></a>
  <img alt="CVSS" src="https://img.shields.io/badge/CVSS%20v4.0-9.2-c0392b">
  <img alt="affected PHP" src="https://img.shields.io/badge/affected%20PHP-5.4.0%20%E2%80%93%208.5.11-c0392b">
  <img alt="fixed PHP" src="https://img.shields.io/badge/fixed-8.5.12%20%2F%208.4.27%20%2F%208.3.36%20%2F%208.2.35-2e8b57">
</p>

<h3 align="center">A remote scanner and research PoC for the PHP2SHELL RCE pair —<br>reverse-engineered from the PHP 8.5.11 → 8.5.12 source diff, informed by the<br>Wiz / Calif / OpenAI research, and verified against both builds — including a<br>laboratory reproduction of the cross-request stale-state corruption.</h3>

<p align="center">
  <a href="#run-it">Run it</a> ·
  <a href="#what-php2shell-is">What PHP2SHELL is</a> ·
  <a href="#how-the-scanner-works">How it works</a> ·
  <a href="#verdicts">Verdicts</a> ·
  <a href="#lab-finding--the-corruption-reproduced">The corruption, reproduced</a> ·
  <a href="#research-poc">Research PoC</a> ·
  <a href="#evidence">Evidence</a> ·
  <a href="#mitigations">Mitigations</a> ·
  <a href="#ethics--authorization">Ethics</a>
</p>

<details>
<summary>The launch banner (what you see when it runs)</summary>

```text
██████╗ ██╗  ██╗██████╗ ██████╗ ███████╗██╗  ██╗███████╗██╗     ██╗
██╔══██╗██║  ██║██╔══██╗╚════██╗██╔════╝██║  ██║██╔════╝██║     ██║
██████╔╝███████║██████╔╝ █████╔╝███████╗███████║█████╗  ██║     ██║
██╔═══╝ ██╔══██║██╔═══╝ ██╔═══╝ ╚════██║██╔══██║██╔══╝  ██║     ██║
██║     ██║  ██║██║     ███████╗███████║██║  ██║███████╗███████╗███████╗
╚═╝     ╚═╝  ╚═╝╚═╝     ╚══════╝╚══════╝╚═╝  ╚═╝╚══════╝╚══════╝╚══════╝
 CVE-2026-109618 · CVE-2026-109619 · PHP 5.4.0–8.5.11 · fixed 8.5.12/8.4.27/8.3.36/8.2.35

  [2] HashTable amplification probe: 2500 nested empty file fields + upload-progress + PHPSESSID cookie (~0.30 MB)
  {"what_probe": "hash_amplification", "parts": 2500, "status": 200, "oom": true, ...}
    >>> WORKER DIED on follow-up — stale-state corruption

========================================================================
VERDICT
  VULNERABLE — cross-request stale-state corruption observed
```

</details>

## Run it

One file, zero dependencies, Python 3.7+ stdlib only. Clone and run:

```sh
git clone https://github.com/roloVibes/php2shell && cd php2shell
./php2shell.py https://target.example.com/upload.php --yes-i-own-or-authorized
```

`--yes-i-own-or-authorized` is **required** — the tool refuses to send
anything without it. Add `--json` for machine-readable findings,
`--hash-parts N` / `--max-field-mb N` to tune probe sizes.

That's the whole install. There is nothing else.

## What PHP2SHELL is

PHP's `rfc1867` multipart POST parser runs **before any userland PHP code**,
in the same process as the request. PHP2SHELL (the name comes from Wiz
Research's combined exploit script) is a pair of CVEs on that path, each
rated **9.2 CVSS v4.0**, fixed 2026-10-21 after coordinated disclosure by
Wiz, Calif and OpenAI:

| CVE | Bug instances (per Wiz) | Impact |
|---|---|---|
| **CVE-2026-109618** | Upload-progress unserializer use-after-free · remote process-memory disclosure | Pre-auth RCE on WordPress, Drupal, Joomla; application-agnostic memory disclosure |
| **CVE-2026-109619** | Fatal-error backtrace use-after-free · OPcache type confusion | Pre-auth RCE (Drupal via backtrace, WordPress via OPcache); corrupt shared state |

The core defect: when the pre-request parser hits `memory_limit`, memory can
be visible to cleanup **before it is initialized** (the HashTable
count-then-key-alloc-fail primitive), and process globals (`PS(id)`,
`EG(last_fatal_error_backtrace)`, `BG(unserialize)`, OPcache pointer maps)
can keep pointing into freed request memory. Every PHP release back to 5.4
is affected by at least one instance. **All web SAPIs are in scope** —
PHP-FPM, Apache mod_php (highest risk: the demonstrated path fires before
application code), php-cgi, FrankenPHP, LiteSpeed.

**Affected:** PHP 5.4.0 – 8.5.11. **Fixed:** 8.5.12 / 8.4.27 / 8.3.36 /
8.2.35. PHP ≤ 8.1 gets no upstream release (limited source backports exist
for 7.4/8.0/8.1). Active probing in the wild was observed from 2026-10-21
(Unit 42 estimates 22.6M exposed instances).

## How the scanner works

Four probes, cheapest and strongest first:

1. **Fingerprint** — `X-Powered-By` / `Server` / leaked version strings,
   classified against the fixed set.
2. **HashTable amplification probe** (~0.3 MB) — 2500 nested *empty file
   fields* build several metadata trees per part (~18× heap amplification,
   measured), with a `PHP_SESSION_UPLOAD_PROGRESS` field and a `PHPSESSID`
   cookie so the session module's early path engages. Three possible
   signals: the `zend_hash.c` OOM (the corruption primitive), a follow-up
   request that **kills the worker** (stale-state corruption), or nothing
   (PHP's default `max_file_uploads=20` caps the path — a documented edge
   mitigation, itself worth knowing).
3. **Text-field OOM sweep** (16 MB → ×2, cap 256 MB) — only if the cheap
   probe gave nothing. One oversized text field trips the parser's
   body-buffer allocation (`rfc1867.c:632` on 8.5.11 vs `:665` on 8.5.12).
   File uploads *stream to disk* — they are not a trigger.
4. **Stale-state + disclosure checks** — identical small requests before and
   after the OOM (divergence = 109619 signal), and a `Set-Cookie: PHPSESSID`
   anomaly check on every response: an oversized or malformed PHPSESSID is
   the published signature of the stale-`PS(id)` memory disclosure (heap
   contents URL-encoded into the cookie).

## Verdicts

| Verdict | Exit | Meaning |
|---|---|---|
| `VULNERABLE — cross-request stale-state corruption observed` | **2** | after the HashTable OOM, the follow-up request killed the worker |
| `VULNERABLE — memory disclosure signature observed` | **2** | anomalous PHPSESSID Set-Cookie |
| `VULNERABLE` | **2** | parser/HashTable OOM + pre-fix (or unknown) version |
| `LIKELY VULNERABLE` | **3** | worker crashed on a probe + pre-fix version, or pre-fix version with no OOM at probe caps |
| `NOT VULNERABLE` | 0 | fixed version reported (with the distro-backport caveat) |
| `INCONCLUSIVE` | 0 | crash seen but version fixed/unidentifiable — investigate |
| (error) | 1 | unreachable / refused / no authorization flag |

**display_errors matters.** With `display_errors=1` the fatal text lands in
the body and leaks both `memory_limit` and the exact `.c:NNN` site — the
strongest passive signal. With `display_errors=0` both builds answer HTTP
5xx with an empty body, so the crash alone cannot tell 8.5.11 from 8.5.12 —
the version string decides. The scanner never upgrades a signal it did not
measure and never calls a fixed build "vulnerable"; every version-based
`NOT VULNERABLE` carries the caveat that a banner cannot prove a distro
backport.

## Lab finding — the corruption, reproduced

The strongest result in this repo, verified against locally built 8.5.11 and
8.5.12 (session module enabled) and now encoded in both the scanner and the
PoC:

| Step | 8.5.11 (vulnerable) | 8.5.12 (fixed) |
|---|---|---|
| 2500 nested empty file fields + upload-progress + `PHPSESSID` cookie | OOM at `zend_hash.c:290` (HashTable corruption primitive) | OOM at `zend_hash.c:244`, **deferred**, request completes |
| follow-up upload-progress request | **worker dies** (segfault / abort trap — 4/4 deterministic) | 200 OK, every time |
| control: same probe, no cookie | OOM at `zend_hash.c:176`, follow-up **survives** | — |
| control: text-field OOM + cookie | OOM at `rfc1867.c:632`, follow-up **survives** | — |
| control: default `max_file_uploads=20` | no OOM at all (edge mitigation works) | — |

The `PHPSESSID` cookie is the discriminator — exactly Wiz's `PS(id)` path:
without a session cookie the stale pointer is never published, and the
follow-up survives. The crash is specific to the HashTable allocation path,
not the body-buffer path. One honest negative: the *memory-disclosure* form
(heap contents URL-encoded into `PHPSESSID`) did not reproduce on the
single-process dev server — follow-ups there carry fresh, normal-length
session IDs. The corruption crash reproduces every time.

## Research PoC

`poc/php2shell_poc.py` drives **your own local builds** of 8.5.11 and 8.5.12
and proves the mechanics end to end:

- **R1** — OOM fires inside the vulnerable pre-request parser (runtime).
- **R2** — plain next-request `$_POST` probe (honest negative, with reason).
- **R3** — fix-mechanism fingerprint: every 8.5.12-only marker
  (`EG(delayed_oom)`, `ZEND_HAS_OOM` checks, `http_globals` `ZVAL_UNDEF`,
  `modules_activated` reset, `memory_hard_limit_percent`, `_exit(137)`)
  present in 8.5.12 and provably absent from 8.5.11.
- **R4** — CGI exit-code mapping, including the honest negative that
  exit-121 needs the custom-heap `ZEND_MM_MAX_ALLOCS` hook (unreachable in
  NTS builds).
- **R5** — the full HashTable amplification + cross-request corruption
  differential, with all four controls from the table above.

Prerequisites: unpacked, built PHP 8.5.11 and 8.5.12 trees
(`--enable-session --enable-cgi`) under `~/php2shell-lab/php-8.5.11` and
`~/php2shell-lab/php-8.5.12`, or point `$PHP2SHELL_LAB` at the root:

```sh
export PHP2SHELL_LAB=~/php2shell-lab
python3 poc/php2shell_poc.py     # exit 0 = every assertion held
```

The full write-up — diff analysis, the four bug instances, the disclosure
timeline, and why the trigger is a *text* field or *nested empty files* and
never a plain upload — is in
[docs/REVERSE-ENGINEERING.md](docs/REVERSE-ENGINEERING.md), with the raw
diffs in [docs/diffs/](docs/diffs/).

## Evidence

Captured runs in [evidence/](evidence/) (paths scrubbed):

| Log | Config | Verdict | Exit |
|---|---|---|---|
| `scanner-8711-HASH.log` | 8.5.11, `max_file_uploads` lifted, DE=1 | **VULNERABLE — stale-state corruption observed** | 2 |
| `scanner-8712-HASH.log` | 8.5.12, `max_file_uploads` lifted, DE=1 | NOT VULNERABLE (deferred) | 0 |
| `scanner-8711-DE1.log` | 8.5.11, defaults, DE=1 | VULNERABLE (`rfc1867.c:632`) | 2 |
| `scanner-8711-DE0.log` | 8.5.11, defaults, DE=0 | LIKELY VULNERABLE | 3 |
| `scanner-8712-DE1.log` | 8.5.12, defaults, DE=1 | NOT VULNERABLE (`rfc1867.c:665`) | 0 |
| `scanner-8712-DE0.log` | 8.5.12, defaults, DE=0 | INCONCLUSIVE | 0 |
| `poc-run.log` | full PoC, both builds | R1/R3/R5 CONFIRMED | 0 |

## Mitigations

Patching is the only complete fix. While updating, the scanner prints this
guidance with every positive verdict:

- **Update** to 8.5.12 / 8.4.27 / 8.3.36 / 8.2.35 (or a distro backport) and
  **restart/replace every PHP worker**.
- `memory_limit=-1` administratively (`php_admin_value`) — removes the
  predictable 109618 trigger; verify no pool/dir/app setting restores it.
- `session.upload_progress.enabled=0` in php.ini / FPM / server config
  **applied before request parsing** — `ini_set()` and `.user.ini` are too
  late for the confirmed early session paths.
- PHP 8.5: `fatal_error_backtraces=0` administratively.
- FPM: `pm.max_requests=1` interrupts cross-request chains (performance cost).
- Edge limits on decoded request size, multipart parts, nesting depth.

Detection guidance (Wiz): unusual multipart requests followed by
memory-limit errors or repeated HTTP 500s, unexpectedly large or malformed
`PHPSESSID` response cookies, unexplained PHP worker churn.

## Ethics & authorization

The scanner **refuses to run** without `--yes-i-own-or-authorized`. Probes
are visible in access logs and can be flagged by WAFs. Run only against
targets you own or have written permission to test. Published for defenders
and researchers — detection and verification, not weaponization; no RCE
payload is included. Credit for the vulnerability research belongs to Wiz
Research, Calif, OpenAI and the PHP team; the HTB War Room article informed
parts of this update.
