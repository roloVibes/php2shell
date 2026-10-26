#!/usr/bin/env python3
"""
PHP2SHELL remote scanner — CVE-2026-109618 / CVE-2026-109619 (PHP 5.4.0 - 8.5.11)
=================================================================================
Checks whether a TARGET you own or are authorized to test is running a
vulnerable PHP build, using the same mechanics that were proven in the
local lab (~/php2shell-lab):

  * The rfc1867 multipart parser runs before any userland PHP. An oversized
    TEXT field forces its body-buffer allocation past memory_limit ->
    "Allowed memory size of N bytes exhausted at .../main/rfc1867.c:NNN".
    (Lab: 8.5.11 rfc1867.c:632, 8.5.12 rfc1867.c:665 — same code path.)
  * With display_errors=1 that fatal text lands in the response body and is
    the PRIMARY detector (it leaks the server's memory_limit and the exact
    .c:NNN site). With display_errors=0 both pre-fix and fixed builds die
    with an HTTP 5xx and an empty body — the crash alone cannot tell them
    apart, so the version string decides (see README).
  * File-part uploads do NOT trigger it (streamed to disk) — use text fields.
  * The sweep doubles the field size from 16 MB up to --max-field-mb.
  * After the OOM, a repeat small POST that answers DIFFERENTLY than a
    baseline is the 109619 stale-state signal.
  * Version fingerprint (X-Powered-By / Server / leak page) + the
    post-fix release set (8.5.12 / 8.4.27 / 8.3.36 / 8.2.35) refines the
    verdict. If the version is in the fixed set, the OOM path may not be
    the parser — report what was actually seen.

AUTHORIZATION: run this only against sites you own or have written
permission to test. The probe is a large multipart POST — it can be seen
in access logs.

Exit codes: 0 = NOT VULNERABLE / inconclusive-clean, 2 = VULNERABLE,
            3 = LIKELY VULNERABLE, 1 = scanner error.

Stdlib only (Python 3.7+).
"""
import argparse
import json
import os
import random
import re
import socket
import string
import sys
import time
import urllib.error
import urllib.request

USER_AGENT = "php2shell-scanner/1.0 (authorized security research)"
TIMEOUT = 25
MAX_STEPS = 8
OOM_RE = re.compile(
    r"Allowed memory size of (\d+) bytes exhausted at ([^\s()]+\.c):(\d+)")
VERSION_RE = re.compile(r"PHP/?\s*(\d+\.\d+(?:\.\d+)?)")

# Post-fix releases (NVD: fixed 2026-10-21). A version AT OR ABOVE the
# fixed patch for its branch is NOT vulnerable.
FIXED_MIN = {
    "8.5": (8, 5, 12),
    "8.4": (8, 4, 27),
    "8.3": (8, 3, 36),
    "8.2": (8, 2, 35),
    "8.1": (8, 1, 0),   # 8.1 EOL before the fix — treat as in-range, flag it
    "8.0": (8, 0, 0),
    "7.4": (7, 4, 0),
    "7.3": (7, 3, 0),
    "7.2": (7, 2, 0),
    "7.1": (7, 1, 0),
    "7.0": (7, 0, 0),
    "5.6": (5, 6, 0),
    "5.5": (5, 5, 0),
    "5.4": (5, 4, 0),
}


def parse_ver(v):
    parts = [int(x) for x in v.split(".")[:3]]
    while len(parts) < 3:
        parts.append(0)
    return tuple(parts)


def version_status(version):
    """'fixed', 'vulnerable', or 'unknown' for a dotted version string."""
    v = version.strip()
    # Match a bare dotted version OR the X-Powered-By "PHP/x.y.z" form.
    m = re.search(r"(\d+\.\d+(?:\.\d+)?)", v)
    if not m:
        return "unknown"
    dotted = m.group(1)
    major_minor = ".".join(dotted.split(".")[:2])
    if major_minor not in FIXED_MIN:
        return "unknown"
    if parse_ver(dotted) >= FIXED_MIN[major_minor]:
        return "fixed"
    return "vulnerable"


def boundary():
    return "----PHP2SHELL-" + "".join(
        random.choice(string.ascii_letters + string.digits) for _ in range(16))


def build_multipart(bound, field_name, value):
    return (
        ("--%s\r\n" % bound).encode() +
        ('Content-Disposition: form-data; name="%s"\r\n' % field_name).encode() +
        b"Content-Type: text/plain\r\n\r\n" +
        value +
        b"\r\n" +
        ("--%s--\r\n" % bound).encode()
    )


def http_request(url, method, headers, body=None, timeout=TIMEOUT):
    """Returns (status, body_bytes, wall_seconds, err). Never raises."""
    req = urllib.request.Request(url, data=body, method=method)
    for k, v in headers.items():
        req.add_header(k, v)
    t0 = time.monotonic()
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            data = r.read()
            return r.status, data, time.monotonic() - t0, None
    except urllib.error.HTTPError as e:
        try:
            data = e.read()
        except Exception:
            data = b""
        return e.code, data, time.monotonic() - t0, None
    except Exception as e:
        return None, b"", time.monotonic() - t0, repr(e)


class Scanner:
    def __init__(self, url, max_field):
        self.url = url
        self.max_field = max_field
        self.findings = []

    def log(self, msg):
        print("  %s" % msg, flush=True)

    def record(self, what, **kw):
        self.findings.append(dict(what=what, **kw))
        self.log("%s" % json.dumps(kw)[:160])

    # -- step 1: fingerprint ------------------------------------------------
    def fingerprint(self):
        self.log("[1] fingerprinting %s" % self.url)
        req = urllib.request.Request(self.url, method="GET",
                                     headers={"User-Agent": USER_AGENT})
        t0 = time.monotonic()
        try:
            with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
                status = r.status
                headers_blob = str(r.headers)
                body = r.read()
        except urllib.error.HTTPError as e:
            status = e.code
            headers_blob = str(e.headers)
            try:
                body = e.read()
            except Exception:
                body = b""
        except Exception as e:
            self.record("unreachable", error=repr(e))
            raise SystemExit(1)
        dt = time.monotonic() - t0
        blob = (headers_blob + "\n" + body[:65536].decode("utf-8", "replace"))
        versions = sorted(set(m.group(1) for m in VERSION_RE.finditer(blob)))
        xpb = None
        m = re.search(r"X-Powered-By:\s*(PHP/\S+)", blob, re.I)
        if m:
            xpb = m.group(1)
        srv = re.search(r"Server:\s*([^\r\n]+)", blob, re.I)
        self.record("fingerprint", status=status, php_versions=versions,
                    x_powered_by=xpb, server=srv.group(1) if srv else None,
                    get_seconds=round(dt, 3))
        verdicts = [version_status(v) for v in versions]
        best = "unknown"
        if any(v == "vulnerable" for v in verdicts):
            best = "vulnerable"
        elif any(v == "fixed" for v in verdicts):
            best = "fixed"
        return versions, best, dt

    # -- step 2: POST acceptance + baseline ---------------------------------
    def baseline_post(self, bound, size):
        body = build_multipart(bound, "f", b"A" * size)
        hdrs = {"User-Agent": USER_AGENT,
                "Content-Type": "multipart/form-data; boundary=" + bound}
        status, resp, dt, err = http_request(self.url, "POST", hdrs, body)
        return status, resp, dt, err

    # -- step 3: OOM sweep ----------------------------------------------------
    def oom_sweep(self, bound, versions, ver_status):
        self.log("[2] probing rfc1867 OOM (text field sweep, cap %d MB)"
                 % (self.max_field // 1048576))
        size = 16 * 1048576   # OOMs a 4M-limit lab build at ~16MB field
        baseline = None
        last = None
        step = 0
        while size <= self.max_field and step < MAX_STEPS:
            if step == 0:
                bstatus, bresp, bdt, berr = self.baseline_post(bound, 256)
                if bstatus is None:
                    self.record("post_refused", error=berr)
                    return None
                baseline = {"status": bstatus, "seconds": round(bdt, 3),
                            "body_prefix": bresp[:200].decode("utf-8", "replace")}
                self.record("baseline_small_post", **baseline)

            self.log("  POST text field %d MB ..." % (size // 1048576))
            body = build_multipart(bound, "f", b"B" * size)
            hdrs = {"User-Agent": USER_AGENT,
                    "Content-Type": "multipart/form-data; boundary=" + bound}
            status, resp, dt, err = http_request(self.url, "POST", hdrs, body)
            text = resp.decode("utf-8", "replace")
            last = {"step": step + 1, "field_mb": size // 1048576,
                    "status": status, "seconds": round(dt, 3),
                    "error": err}

            m = OOM_RE.search(text)
            if m:
                limit = int(m.group(1))
                file = m.group(2)
                last.update(oom=True, memory_limit_bytes=limit,
                            oom_site="%s:%s" % (file, m.group(3)),
                            fatal_excerpt=re.sub(r"\s+", " ", text)[:300])
                in_rfc1867 = "rfc1867" in file
                self.record("oom_fatal_observed", **last)
                if in_rfc1867:
                    return last
                # OOM in userland instead — parser survived. Record and stop.
                self.log("  NOTE: OOM was in %s, not rfc1867 — userland, "
                         "not the CVE path" % file)
                return last
            if status is None or (isinstance(status, int) and status >= 500
                                  and not text.strip()):
                # Connection died mid-POST, or a 5xx with no body, while the
                # small baseline POST succeeded: worker crash. display_errors=0
                # hides the fatal text — the crash itself is the signal.
                last.update(crash_signal=True,
                            note="worker died on oversized POST (HTTP %s / %s) "
                                 "while a small POST was fine — consistent "
                                 "with an unhandled OOM fatal in the request "
                                 "path (CVE-2026-109618)" % (status, err))
                self.record("oom_crash_signal", **last)
                return last

            step += 1
            size = size * 2

        # No OOM seen at any step
        self.record("no_oom_observed", last_post=last,
                    note="server memory_limit higher than %d MB, or "
                         "post_max_size capped the body before the buffer "
                         "path, or OOM was hidden" % (size // 1048576))
        return None

    # -- step 4: stale-state check (109619) ----------------------------------
    def stale_check(self, bound):
        self.log("[3] stale-state check: identical small POSTs before/after OOM")
        body = build_multipart(bound, "x", b"1")
        hdrs = {"User-Agent": USER_AGENT,
                "Content-Type": "multipart/form-data; boundary=" + bound}
        s1, r1, dt1, _ = http_request(self.url, "POST", hdrs, body)
        s2, r2, dt2, _ = http_request(self.url, "POST", hdrs, body)
        identical = (r1 == r2)
        self.record("stale_state_probe",
                    first=(s1, r1[:120].decode("utf-8", "replace")),
                    second=(s2, r2[:120].decode("utf-8", "replace")),
                    identical_responses=identical,
                    note="divergence after OOM = 109619 stale-state signal; "
                         "identical = no cross-request contamination seen")
        return not identical


def main():
    ap = argparse.ArgumentParser(
        description="PHP2SHELL (CVE-2026-109618/109619) scanner. "
                    "AUTHORIZED TARGETS ONLY.")
    ap.add_argument("target", help="http(s)://host:port/path you are "
                                   "authorized to test")
    ap.add_argument("--max-field-mb", type=int, default=256,
                    help="max oversized text field in MB (default 256)")
    ap.add_argument("--yes-i-own-or-authorized", action="store_true",
                    help="confirm authorization to probe this host")
    ap.add_argument("--json", action="store_true",
                    help="also print a JSON findings block")
    args = ap.parse_args()

    if not args.yes_i_own_or_authorized:
        print("Refusing: this probe sends a multi-MB POST to a remote host.")
        print("Pass --yes-i-own-or-authorized only if you own the target or")
        print("have written permission to test it.")
        sys.exit(1)

    if not re.match(r"^https?://", args.target):
        print("Target must be an http(s):// URL, got: %s" % args.target)
        sys.exit(1)

    print("=" * 72)
    print("PHP2SHELL scanner — CVE-2026-109618 / CVE-2026-109619")
    print("Target: %s" % args.target)
    print("=" * 72)

    sc = Scanner(args.target, args.max_field_mb * 1048576)
    bound = boundary()

    versions, ver_status, get_dt = sc.fingerprint()

    oom = None
    # If the fingerprint already says a FIXED version, still run ONE probe so
    # the verdict is evidence-based, not version-trust-based.
    oom = sc.oom_sweep(bound, versions, ver_status)

    crash = bool(oom and oom.get("crash_signal"))
    oom_rf = bool(oom and oom.get("oom") and "rfc1867" in oom.get("oom_site", ""))
    if oom_rf or crash:
        sc.stale_check(bound)
    else:
        sc.log("[3] stale-state check skipped (no rfc1867 OOM observed)")

    # ---- verdict -----------------------------------------------------------
    print("\n" + "=" * 72)
    print("VERDICT")
    print("=" * 72)
    oom_site = (oom or {}).get("oom_site", "")
    rfc1867 = "rfc1867" in oom_site
    leak = "Allowed memory size" in json.dumps(sc.findings)

    if rfc1867 and ver_status in ("vulnerable", "unknown"):
        verdict = "VULNERABLE"
        code = 2
        detail = ("OOM fatal fired inside the rfc1867 pre-request parser at %s; "
                  "reported PHP %s (%s). This is the PHP2SHELL OOM-RCE path "
                  "(CVE-2026-109618) on a pre-fix build." %
                  (oom_site, versions or "unidentified", ver_status))
    elif crash and ver_status in ("vulnerable", "unknown"):
        # No fatal text (display_errors=0) but the worker died on the oversized
        # POST while small POSTs are fine — the crash is in the request path.
        verdict = ("LIKELY VULNERABLE (worker crashed on oversized POST; "
                   "pre-fix build reported)")
        code = 3
        detail = ("An oversized text field crashed the worker (HTTP %s / %s) "
                  "while small POSTs succeeded, and PHP reports %s (%s) — a "
                  "pre-fix build. On pre-fix 8.5.11 an rfc1867 OOM is fatal "
                  "and not recovered, which is exactly this crash. "
                  "(CVE-2026-109618.)" %
                  (oom.get("status"), oom.get("error"),
                   versions or "unidentified", ver_status))
    elif rfc1867:
        verdict = "NOT VULNERABLE (fixed build reported; OOM deferred, not fatal)"
        code = 0
        detail = ("The parser OOMed at %s but PHP reports %s (%s), which is "
                  "in the fixed set (8.5.12+). On a fixed build the rfc1867 "
                  "OOM is deferred and recovered, not fatal — no RCE. If the "
                  "version string looks wrong, treat as unverified." %
                  (oom_site, versions or "unidentified", ver_status))
    elif crash:
        verdict = ("INCONCLUSIVE (worker crashed on oversized POST; version "
                   "not in affected range or unknown)")
        code = 0
        detail = ("A worker crash on the oversized POST was seen (HTTP %s), "
                  "but the reported version %s (%s) is a fixed build or "
                  "unidentifiable. A fixed build defers the OOM — but a "
                  "worker still crashed, so either the version is misreported "
                  "or the crash is unrelated (a 502 from a proxy, a different "
                  "limit). Investigate before ruling safe." %
                  (oom.get("status"), versions or "unidentified", ver_status))
    elif leak and not rfc1867:
        verdict = "PARTIAL (OOM in userland only — not the CVE parser path)"
        code = 0
        detail = ("A memory-exhaustion fatal was seen, but outside rfc1867. "
                  "The PHP2SHELL vector specifically requires the parser "
                  "path; re-run with a larger --max-field-mb if memory_limit "
                  "is high.")
    elif ver_status == "vulnerable":
        verdict = "LIKELY VULNERABLE (version in affected range; OOM not " \
                  "observed at probe cap)"
        code = 3
        detail = ("PHP %s reports a pre-fix build, but the oversized POST "
                  "did not trip the parser OOM at %d MB — memory_limit may "
                  "be above the probe, or post_max_size capped the body. "
                  "Treat as vulnerable until proven otherwise." %
                  (versions or "", args.max_field_mb))
    elif ver_status == "fixed":
        verdict = "NOT VULNERABLE (fixed build reported; no OOM observed)"
        code = 0
        detail = ("PHP reports %s, in the fixed set, and no OOM/crash was "
                  "observed at the %d MB probe cap." %
                  (versions, args.max_field_mb))
    else:
        verdict = "INCONCLUSIVE"
        code = 0
        detail = ("No OOM, no crash, and the PHP version could not be "
                  "identified or is outside the known affected set. "
                  "Fingerprint the host another way.")

    print("  %s" % verdict)
    print("  " + detail)
    if oom:
        lim = oom.get("memory_limit_bytes")
        if lim:
            print("  observed memory_limit: %d bytes (%.1f MiB)" %
                  (lim, lim / 1048576))
            print("  fatal site: %s" % oom_site)
        print("  oversized POST: %d MB, HTTP %s, %.2fs" %
              (oom.get("field_mb", 0), oom.get("status"), oom.get("seconds", 0)))
    print("\n  Authorization reminder: this probe is visible in access logs.")
    print("  Run only on targets you own or are authorized to test.")

    if args.json:
        print("\nJSON FINDINGS")
        print(json.dumps({"target": args.target, "verdict": verdict,
                          "php_versions": versions,
                          "version_status": ver_status,
                          "findings": sc.findings}, indent=2))

    sys.exit(code)


if __name__ == "__main__":
    main()
