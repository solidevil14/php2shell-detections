# php2shell-detections

[![rules-regression](https://img.shields.io/github/actions/workflow/status/YOUR_GH_USER/php2shell-detections/test.yml?branch=main&label=rules%20regression)](../../actions)

Suricata 7.x signature set for detecting the **php2shell** toolkit
(CVE-2026-109619 / CVE-2026-109618 — PHP `session.upload_progress` UAF/OOM
chain), plus a test harness that proves coverage on every push: byte-exact
exploit traffic built with the upstream toolkit's own request builders, a
false-positive regression set, and an end-to-end run of the real CLI.

> ⚠️ **What this is**: detection engineering (blue/purple team). The harness
> only ever talks to a local mock target (127.0.0.1). Pointing php2shell at
> systems you don't own or don't have authorization for is a crime (CFAA,
> UU ITE, etc.) — don't.

## Layout

```
rules/php2shell.rules    14 SIDs (13 alert rules + 1 flowbit setter), 1100001-1100015
lab/gen_traffic.py       byte-exact traffic generator (imports upstream builders)
lab/pcap_build.py        pure-python pcap writer (correct TCP/IP checksums)
lab/mock_target.py       behavioral replica of a vulnerable PHP 8.4.26 target
lab/tee_proxy.py         per-connection byte recorder (real CLI -> wire capture)
lab/run_real.py          full pipeline: real CLI -> pcap -> offline Suricata
lab/make_lab_config.py   lab suricata.yaml derived from the system default
lab/test_matrix.py       THE regression suite (alerts matrix assertions; exit code)
docs/SIGNALS.md          every signal: source location in upstream code, FP guards
docs/TUNING.md           production tuning, TLS placement, IPS guidance, engine quirks
.github/workflows/       CI: suite runs on every push
```

## Quick start

```bash
# requires: suricata 7.x, python3, git
git clone --depth 1 https://github.com/aarsaputra/php2shell.git /tmp/php2shell
python3 lab/test_matrix.py --skip-real     # synthetic + benign-only

# full suite, incl. the real CLI end-to-end (needs curl_cffi + bcrypt):
python3 -m venv /tmp/php2shell/.venv
/tmp/php2shell/.venv/bin/pip install -r /tmp/php2shell/requirements.txt
python3 lab/test_matrix.py                 # exit 0 = pass
```

Expected output:

```
[attack] alerts-by-sid: {1100001: 3, 1100002: 3, ...} total: 28
[benign] alerts-by-sid: {} total: 0
[PASS] test_matrix: attack coverage complete, benign clean
```

Environment knobs: `SURICATA_BIN` (binary path), `SURICATA_CONF` (base yaml),
`P2S_REPO` (upstream clone location; default `../php2shell`).

## Alert matrix (baseline: Suricata 7.0.10)

**attack.pcap** — full chain: rotate → stage1 → stage2 → stage3:

| SID | Signal | Hits |
|---|---|---|
| 1100001 | chain groom request (boundary `S×17`) | 3 |
| 1100002 | chain forge request (boundary `B×10` + `PHPSESSID` form-data) | 3 |
| 1100003 | worker-rotate request (`BNDRY12345`) | 1 |
| 1100004 | heap-leak response: `Set-Cookie: PHPSESSID=` ≥990B | 2 |
| 1100005 | leaked cookie carrying `%7F`-encoded pointer (stage-2 leak) | 2 |
| 1100006 | oversized multipart POST (>10MB) + upload_progress (flowbit pair) | 1 |
| 1100007 | nested-62 array key (`a[b][b]…×61`, active scanner) | 2 |
| 1100008 | detect probe boundary `----php2shellprobe` | 1 |
| 1100009 | memory_limit probe `P2SMEMPROBE` | 1 |
| 1100010 | quoted single-char multipart boundary (`boundary="x"`) | 2 |
| 1100012 | OOM fatal inside the multipart parser (`Unknown` location) | 1¹ |
| 1100013 | worker-abort 5xx differential (xbits correlation) | 4 |
| 1100014 | `PHP_SESSION_UPLOAD_PROGRESS` + `PHPSESSID` form-field pairing | 5 |

¹ `threshold limit 1/60s by_dst` — three scanner probes from one client
produce one alert.

**benign.pcap** (false-positive regression) — normal browser upload using
`PHP_SESSION_UPLOAD_PROGRESS` (a legitimate app feature!), a normal PHPSESSID
cookie, an HTTP 500 with an OOM fatal **inside application code** (`in
/var/www/... on line 42`), an 11MB upload without upload_progress, plain GET
— **0 alerts**.

**Real-tool end-to-end** (`run_real.py`; CLI v1.5.1 driving the mock target
until it prints `PROOF: uid=33(www-data)`): **63 alerts, 13/13 alert rules
fired** — every stage of the real chain is caught by at least one rule per
request, including retries.

## Production tuning

The ruleset requires:

```yaml
# suricata.yaml -> stream -> reassembly -> libhtp
request-body-limit: 32mb      # default 100kb truncates 12MB bodies -> body rules die
response-body-limit: 1mb
```

Sensor placement and IPS-drop guidance: **docs/TUNING.md**. per-signal
details and FP guards: **docs/SIGNALS.md**.

## Provenance

Signatures are facts about public toolkit behavior, not guesswork: generated
from the upstream `aarsaputra/php2shell` source (pinned at `1ba7168` in CI,
consumed read-only by `gen_traffic.py`/`run_real.py`) — `lib/chain.py`
(`build_multipart`, `SID`, `_fake_payload`), `lib/oomprobe.py`
(`_nested_name`, `_classify_response` signals S1–S4), `lib/memprobe.py`,
`lib/detect.py`. Active-detection methodology follows the public
assetnote/php2shell-scanner approach (graded 1/8/20 MiB probes,
fatal-in-parser / empty-500 differential signals); original research by
Wiz Research.

## License

MIT — see [LICENSE](LICENSE).
