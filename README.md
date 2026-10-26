<p align="center">
  <img alt="PHP2SHELL" src="https://img.shields.io/badge/PHP2SHELL-CVE--2026--109618%20%2B%20CVE--2026--109619-5b4bd6?style=for-the-badge">
</p>

<p align="center">
  <a href="#scanner"><img alt="version 1.0.0" src="https://img.shields.io/badge/version-1.0.0-5b4bd6"></a>
  <img alt="python 3.7+" src="https://img.shields.io/badge/python-3.7%2B-3776ab">
  <img alt="stdlib only" src="https://img.shields.io/badge/dependencies-0-2e8b57">
  <img alt="Linux, macOS" src="https://img.shields.io/badge/platform-Linux%20%7C%20macOS-2b2b2b">
  <a href="LICENSE"><img alt="license" src="https://img.shields.io/badge/license-all%20rights%20reserved-lightgrey"></a>
  <img alt="affected PHP" src="https://img.shields.io/badge/affected%20PHP-5.4.0%20%E2%80%93%208.5.11-c0392b">
  <img alt="fixed PHP" src="https://img.shields.io/badge/fixed-8.5.12%20%2F%208.4.27%20%2F%208.3.36%20%2F%208.2.35-2e8b57">
</p>

<h3 align="center">A remote scanner and research PoC for the PHP2SHELL RCE pair —<br>reverse-engineered from the PHP 8.5.11 → 8.5.12 source diff, verified against both builds.</h3>

<p align="center">
  <a href="#what-php2shell-is">What PHP2SHELL is</a> ·
  <a href="#scanner">Scanner</a> ·
  <a href="#verdicts">Verdicts</a> ·
  <a href="#the-display_errors-discriminator">The display_errors discriminator</a> ·
  <a href="#research-poc">Research PoC</a> ·
  <a href="#reverse-engineering-notes">RE notes</a> ·
  <a href="#evidence">Evidence</a> ·
  <a href="#ethics--authorization">Ethics</a>
</p>

<details>
<summary>Terminal banner (what the scanner prints)</summary>

```text
========================================================================
PHP2SHELL scanner — CVE-2026-109618 / CVE-2026-109619
Target: https://example.com/upload.php
========================================================================
  [1] fingerprinting ...
  [2] probing rfc1867 OOM (text field sweep, cap 256 MB)
    POST text field 16 MB ...
  {"step": 1, "field_mb": 16, "status": 200, "oom": true,
   "oom_site": "/main/rfc1867.c:632", "memory_limit_bytes": 4194304}

========================================================================
VERDICT
========================================================================
  VULNERABLE
  OOM fatal fired inside the rfc1867 pre-request parser at .../main/rfc1867.c:632
```

</details>

## What PHP2SHELL is

PHP's `rfc1867` multipart POST parser runs **before any userland PHP code**,
in the same process as the request. PHP2SHELL is a pair of bugs on that path,
fixed 2026-10-21:

| CVE | What it is |
|---|---|
| **CVE-2026-109618** | An out-of-memory condition in the pre-request parser leaves request memory **uninitialized** — the engine keeps running on stale state. On vulnerable builds the OOM is an immediate `zend_bailout()` longjmp with no OOM state recorded anywhere. |
| **CVE-2026-109619** | Global state (`PG(http_globals)`, `EG(delayed_oom)`) temporarily points **into request memory** and is never reset after the OOM — the next request reads freed state. |

The 8.5.12 fix is a coordinated mechanism, not a one-line patch:
`EG(delayed_oom)` + `zend_handle_delayed_oom()` (OOM is *deferred* to a safe
point instead of a mid-parse bailout), 20 `ZEND_HAS_OOM` checks threaded
through `rfc1867.c`, `ZVAL_UNDEF(&PG(http_globals)[i])` at request shutdown,
a `PG(modules_activated) = 0` reset, a `memory_hard_limit_percent` INI and a
`_exit(137)` hard-limit abort. Every one of those is verifiable in
[docs/diffs/](docs/diffs/) — the raw, complete source diffs this research was
built from.

**Affected:** PHP 5.4.0 – 8.5.11. **Fixed:** 8.5.12 / 8.4.27 / 8.3.36 / 8.2.35.

## Scanner

```sh
python3 scanner/php2shell_scanner.py https://target.example.com/upload.php \
    --yes-i-own-or-authorized
```

Stdlib only, Python 3.7+, no dependencies. Four steps, in order:

1. **Fingerprint** — GET the target, read `X-Powered-By` / `Server` / any
   leaked version string, classify against the fixed set.
2. **Baseline** — a small 256 B multipart POST must succeed.
3. **OOM sweep** — POST one oversized **text** field, doubling from 16 MB to
   `--max-field-mb` (default 256). Text fields are the trigger: file parts
   stream to disk and bypass the in-memory buffer path entirely.
4. **Stale-state check** — two identical small POSTs before/after the OOM;
   a *divergent* response is the CVE-2026-109619 cross-request signal.

`--json` prints a machine-readable findings block. Full option reference:
[scanner/README.md](scanner/README.md).

## Verdicts

| Verdict | Exit | Meaning |
|---|---|---|
| `VULNERABLE` | **2** | rfc1867 OOM fatal observed + version vulnerable/unknown |
| `LIKELY VULNERABLE` | **3** | worker crashed on the oversized POST + pre-fix version |
| `NOT VULNERABLE` | 0 | fixed version reported, or clean |
| `INCONCLUSIVE` | 0 | crash seen but version fixed/unidentifiable — investigate |
| (error) | 1 | unreachable / refused / no authorization flag |

The scanner never upgrades a signal it did not measure, and never calls a
fixed build "vulnerable".

## The display_errors discriminator

The part most scanners would get wrong:

- `display_errors=1` — the fatal text lands in the response body and is the
  **primary detector**: it leaks the server's `memory_limit` *and* the exact
  `.c:NNN` site (8.5.11 dies at `rfc1867.c:632`, 8.5.12 at `rfc1867.c:665`).
- `display_errors=0` — the realistic default — **both builds die with an
  HTTP 5xx and an empty body.** The crash alone cannot tell 8.5.11 from
  8.5.12; the version string decides. The scanner is honest about that:
  `LIKELY VULNERABLE` on a pre-fix version, `INCONCLUSIVE` on a fixed one.

Measured, not assumed — the full 4-config verification matrix is in
[Evidence](#evidence).

## Research PoC

`poc/php2shell_poc.py` drives **your own local builds** of 8.5.11 and 8.5.12
and proves the mechanics end to end:

- **R1** — the OOM fires inside the vulnerable pre-request parser (runtime).
- **R2** — next-request stale-state probe (`$_POST` inspection).
- **R3** — fix-mechanism fingerprint: the 8.5.12-only symbols/INI/hooks are
  **present in 8.5.12 and provably absent from 8.5.11** (source-level, with
  line numbers).
- **R4** — CGI exit-code mapping, including the honest negative: the
  exit-121 path needs the custom-heap `ZEND_MM_MAX_ALLOCS` test hook and is
  unreachable in an NTS build. Measured, not elided.

Prerequisites: unpacked, built PHP 8.5.11 and 8.5.12 trees (`sapi/cli/php`
and `sapi/cgi/php-cgi` present) under `~/php2shell-lab/php-8.5.11` and
`~/php2shell-lab/php-8.5.12`, or point `$PHP2SHELL_LAB` at the root. The PoC
starts its own servers, runs all checks, and exits 0 only when every
assertion holds.

```sh
export PHP2SHELL_LAB=~/php2shell-lab
python3 poc/php2shell_poc.py
```

## Reverse-engineering notes

The full write-up — how the exploit pair was identified from the
8.5.11 → 8.5.12 diff, which hunks carry which fix, and why the trigger is a
16 MB *text* field and not a file upload — is in
[docs/REVERSE-ENGINEERING.md](docs/REVERSE-ENGINEERING.md), with the raw
diffs alongside it in [docs/diffs/](docs/diffs/).

## Evidence

Real captured runs from the verification matrix (paths scrubbed), in
[evidence/](evidence/):

| Build | display_errors | Verdict | Exit |
|---|---|---|---|
| 8.5.11 | 1 | VULNERABLE (`rfc1867.c:632`) | 2 |
| 8.5.11 | 0 | LIKELY VULNERABLE (crash) | 3 |
| 8.5.12 | 1 | NOT VULNERABLE (`rfc1867.c:665`, fixed) | 0 |
| 8.5.12 | 0 | INCONCLUSIVE (crash + fixed version) | 0 |

Plus the PoC's own run log (`evidence/poc-run-postfix.log`) — R1 CONFIRMED,
R3 CONFIRMED.

## Ethics & authorization

The scanner **refuses to run** without `--yes-i-own-or-authorized`. The probe
is a 16–256 MB multipart POST: visible in access logs, possibly flagged by a
WAF, and a DoS-scale request against a small host. Run it only against
targets you own or have written permission to test. This repository is
published for defenders and researchers — detection and verification, not
weaponization; no RCE payload is included.
