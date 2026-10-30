# Signals — sourced from upstream code, not guesswork

Every rule targets an artifact that **exists in the upstream toolkit's
source** (locations reference `lib/` files at the CI-pinned commit
`1ba7168`). That is the difference between auditable detection and
copy-pasted patterns.

## SID registry

| SID | Kind | Signal | Upstream source | MITRE ATT&CK |
|---|---|---|---|---|
| 1100001 | request, critical | boundary `S×17` (`SSSSSSSSSSSSSSSSS`) + `Content-Disposition` | chain.py rotate()/stage1()/stage2()/stage3() first requests: `build_multipart(parts, b"S"*17)` T1190 |
| 1100002 | request, critical | boundary `B×10` (`BBBBBBBBBB`) + `name="PHPSESSID"` as a **form-data field** (not a header!) | stage1()/stage2() second requests + stage3() final: `b"B"*10`, `{"name":"PHPSESSID","data":SID}` (`SID = attacksessionid0001`)  T1190, T1059.004 |
| 1100003 | request, high | boundary `BNDRY12345` + the UP+PHPSESSID field pair | rotate() second request T1190 |
| 1100004 | response, critical | `Set-Cookie: PHPSESSID=` with **≥990** bytes of value before `; path=/` | `parse_cookie()` regex `Set-Cookie: PHPSESSID=([^\r\n]*?); path=/` + `chunk_base_from_cookie()` requires `len(raw) >= 1000` — a legitimate PHP session id is 22–32 chars T1190 |
| 1100005 | response, high | cookie value containing `%7F` (0x7F; leaked pointers live in `0x7F0000000000–0x800000000000`) within 120B of the value start | `libphp_base_from_cookie()`: `raw[8:16]` = pDestructor pointer, same address range check T1190 |
| 1100006 | request, critical | `Content-Length` ≥8 digits (≥10MB) + `PHP_SESSION_UPLOAD_PROGRESS` field in the same body; joined via same-packet flowbits (setter 1100015) | `_big_field()` 12MB default; `memprobe.py` ≥10MB (auto-sized from the target's `memory_limit`) T1190 |
| 1100007 | request, high | 62-level nested array key: `name="a[b][b]…[b]"` | `oomprobe._nested_name()`: `"a" + "[b]"*61` T1595.002 |
| 1100008 | request, high | boundary `----php2shellprobe` + UP field (data `probe`) + `PHPSESSID` field (data `php2shellprobe0001`) | `detect._probe_upload_progress()` body literal T1595.002 |
| 1100009 | request, high | `--P2SMEMPROBE` … `p2smem` literal | `memprobe.py`: `{"name":"PHP_SESSION_UPLOAD_PROGRESS","data":b"p2smem"}`, `boundary=b"P2SMEMPROBE"` T1595.002 |
| 1100010 | request, high | `Content-Type: multipart/form-data; boundary="x"` — quoted, single-char boundary | `oomprobe` line transport: `boundary="x"` T1595.002 |
| 1100012 | response, high | body contains `Allowed memory size of` + `bytes exhausted` + `Unknown` within 130B | `oomprobe._classify_response()` signal **S1**: OOM fatal inside the multipart parser — the same signal the assetnote scanner keys on T1190 |
| 1100013 | response, correlate | HTTP 5xx to a client that recently (300s) sent a marker request (xbit `p2s_probe`) | worker-abort pattern (SIGABRT → empty-500 / 502/503/504 differential) T1190 |
| 1100014 | request, correlate | the form-field pair `name="PHP_SESSION_UPLOAD_PROGRESS"` + `name="PHPSESSID"` in one multipart body | always present in probes + chain requests; near-zero FP: legitimate apps use UP-progress **without** a PHPSESSID form field T1595.002 |
| 1100015 | request, noalert | flowbit setter `p2s_bigpost` from the 8-digit Content-Length pcre | weight carrier for 1100006 (see libhtp note in TUNING) T1190 |

## False-positive guards

- **Parser-OOM vs app-OOM**: an OOM fatal *inside the parser* is located at
  `Unknown on line 0`; an OOM inside application code has a real path
  (`in /path/file.php on line N`). The 130-byte window after "bytes
  exhausted" catches both `in <b>Unknown</b>` (HTML-tagged) and plain-text
  messages, and never matches a file path. Analogous guard in `oomprobe`
  itself: the `POST Content-Length of … exceeds the limit` warning is also
  located at `Unknown` but is a post_max_size reject, not the bug —
  it never contains "Allowed memory size".
- **Leaked cookie**: a legitimate PHP session cookie is 22–32 hex chars;
  ≥990 bytes of value or an encoded `%7F` pointer byte inside it is by
  construction not a real session cookie.
- **PHPSESSID-as-field**: legitimate apps send the session id in a Cookie
  header, not as multipart form-data; the toolkit does the opposite.
- **1100006** requires *both* CL ≥10MB and the UP field in the same request:
  large legit uploads without upload-progress don't fire, legitimate
  upload-progress browsers don't post 10MB single fields.

Cross-signal machinery: `threshold` on 1100012 (`limit 1/60s by_dst`) keeps
the 3-probe scanner burst to one alert; `xbits p2s_probe` (expire 300s,
set on ip_src, checked on ip_dst) correlates abort responses with prior
probe traffic.
