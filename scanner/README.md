# PHP2SHELL scanner

Remote detector for **PHP2SHELL** — the PHP 8.5.11 (and other pre-fix
branches) RCE pair fixed 2026-10-21:

- **CVE-2026-109618** — an OOM in the pre-request `rfc1867` multipart parser
  leaves Zend state uninitialized → RCE.
- **CVE-2026-109619** — a `PG(http_globals)` / `EG(delayed_oom)` global left
  pointing into freed request memory, not reset between requests → RCE.

Affected: PHP 5.4.0 – 8.5.11. Fixed: **8.5.12 / 8.4.27 / 8.3.36 / 8.2.35**
(and every later 8.x).

## Run it

```sh
python3 php2shell_scanner.py http://HOST:PORT/path.php --yes-i-own-or-authorized
```

`--yes-i-own-or-authorized` is **required** — the tool refuses to send the
probe without it. Only run this against hosts you own or have written
permission to test. The probe is a 16–256 MB multipart POST; it is visible
in access logs and may be flagged by a WAF.

Options:
- `--max-field-mb N` — cap on the oversized text field (default 256). The
  sweep doubles from 16 MB until the parser OOMs, or hits the cap.
- `--json` — also print a machine-readable findings block.

## What it does

1. **Fingerprint** — GET the target, read `X-Powered-By` and any version
   string. Classify the version against the fixed set
   (`vulnerable` / `fixed` / `unknown`).
2. **Baseline** — a small 256 B multipart POST must succeed (200).
3. **OOM sweep** — POST a single oversized *text* field (≥16 MB) and look
   for the `rfc1867` memory-exhaustion fatal (`display_errors=1`) or a
   worker crash on the large POST while small POSTs are fine
   (`display_errors=0`).
4. **Stale-state check** — two identical small POSTs before and after the
   OOM; a *divergent* response is the 109619 cross-request signal. (On a
   single-worker dev server this will read identical — that is a lab
   limitation, not a negative.)

## Verdicts and exit codes

| Verdict | When | Exit |
|---|---|---|
| `VULNERABLE` | `rfc1867` OOM fatal observed + version vulnerable/unknown | **2** |
| `LIKELY VULNERABLE` | worker crashed on the oversized POST + version vulnerable/unknown | **3** |
| `NOT VULNERABLE` | OOM path hit but version is in the fixed set, or clean | 0 |
| `INCONCLUSIVE` | crash seen but version fixed/unidentifiable, or no signal at all | 0 |
| (error) | scanner failure / target unreachable / no auth flag | 1 |

**display_errors matters.** With `display_errors=1` the fatal text lands in
the body and the `rfc1867.c:NNN` site is visible (the strongest signal —
8.5.11 reports `rfc1867.c:632`, 8.5.12 reports `rfc1867.c:665`). With
`display_errors=0` (the realistic default) both builds return HTTP 500 with
an empty body, so the *crash alone cannot tell 8.5.11 from 8.5.12* — the
version string decides. The scanner is honest about that: it reports
`LIKELY VULNERABLE` on the pre-fix version and `INCONCLUSIVE` on the fixed
one, and it never calls the fixed build "vulnerable".

## Lab reproduction (local builds)

The probe targets the `rfc1867` parser of a PHP build, not an arbitrary
site. Verified against the locally built 8.5.11 (vulnerable) and 8.5.12
(fixed) in `~/php2shell-lab/php-8.5.XX/`:

```sh
cd ~/php2shell-lab
./php-8.5.11/sapi/cli/php -S 127.0.0.1:8711 -d memory_limit=4M -d post_max_size=64M -d upload_max_filesize=1K -d display_errors=1 -t poc &
./php-8.5.12/sapi/cli/php -S 127.0.0.1:8712 -d memory_limit=4M -d post_max_size=64M -d upload_max_filesize=1K -d display_errors=1 -t poc &
```

| build | display_errors | verdict | exit |
|---|---|---|---|
| 8.5.11 | 1 | VULNERABLE (rfc1867.c:632) | 2 |
| 8.5.11 | 0 | LIKELY VULNERABLE (crash) | 3 |
| 8.5.12 | 1 | NOT VULNERABLE (rfc1867.c:665, fixed) | 0 |
| 8.5.12 | 0 | INCONCLUSIVE (crash + fixed ver) | 0 |

Evidence: [../evidence/](../evidence/) — captured runs for all four combinations.
