# php2shell-detections

[![rules-regression](https://img.shields.io/github/actions/workflow/status/solidevil14/php2shell-detections/test.yml?branch=main&label=rules%20regression)](../../actions/workflows/test.yml)
[![suricata](https://img.shields.io/badge/Suricata-7.0.10-blue)](https://suricata.io)
[![license](https://img.shields.io/github/license/solidevil14/php2shell-detections)](LICENSE)

Suricata signature set for detecting **php2shell** — the unauthenticated PHP
RCE chain targeting `session.upload_progress` (CVE-2026-109619 /
CVE-2026-109618, CVSS 9.2) — shipped with a reproducible test harness that
proves detection coverage and false-positive behavior on every commit.

Every signature is derived from the toolkit's own request/response builders
(`lib/chain.py`, `lib/oomprobe.py`, `lib/memprobe.py`, `lib/detect.py`) —
auditable, versioned against an upstream pin, and regression-tested in CI
against byte-exact exploit traffic **and** the real CLI end-to-end.

> **Scope.** This is defensive tooling (blue/purple team). The harness only
> ever talks to a local mock target. Pointing `php2shell` at systems you do
> not own or lack written authorization for is a crime (CFAA, UU ITE, etc.).

---

## Detection coverage

| Tier | SIDs | What it catches |
|---|---|---|
| **A — exploit chain** | `1100001`–`1100006` | the full 3-stage RCE chain: heap-groom requests, forged-boundary multiparts, leaked `PHPSESSID` heap pointers in responses |
| **B — active scanner** | `1100007`–`1100010` | `detect`/`preflight` probes: nested-62 array keys, tool boundaries, transport quirks |
| **C — target state** | `1100012`–`1100014` | vulnerable-server responses: OOM-fatal inside the multipart parser, worker-abort correlation, probe field-pairing |

**Validated matrix** (Suricata 7.0.10, CI-asserted):

```
attack.pcap  (11 streams, full chain)   -> 28 alerts, 13/13 alert rules
attack-real (real CLI, 32 conns)        -> 63 alerts, 13/13 alert rules
benign.pcap  (FP regression set)        ->  0 alerts
```

<details>
<summary><b>Per-SID breakdown</b></summary>

| SID | Signal | Hits (synthetic / real CLI) |
|---|---|---|
| 1100001 | chain groom request — boundary `S×17` | 3 / 6 |
| 1100002 | chain forge request — boundary `B×10` + `PHPSESSID` form-data | 3 / 7 |
| 1100003 | worker-rotate request — boundary `BNDRY12345` | 1 / 3 |
| 1100004 | heap-leak response — `Set-Cookie: PHPSESSID=` ≥990B | 2 / 1 |
| 1100005 | leaked cookie carrying `%7F`-encoded pointer (libphp-base leak) | 2 / 2 |
| 1100006 | oversized multipart (>10MB) + upload_progress (flowbit pair) | 1 / 4 |
| 1100007 | nested-62 array key `a[b][b]…` (active OOM scanner) | 2 / 6 |
| 1100008 | detect probe — boundary `----php2shellprobe` | 1 / 3 |
| 1100009 | memory_limit probe — `P2SMEMPROBE` / `p2smem` | 1 / 1 |
| 1100010 | quoted single-char boundary (`boundary="x"`) | 2 / 6 |
| 1100012 | OOM fatal inside the multipart parser (`Unknown` location)¹ | 1 / 1 |
| 1100013 | worker-abort 5xx differential (xbits correlation) | 4 / 10 |
| 1100014 | `PHP_SESSION_UPLOAD_PROGRESS` + `PHPSESSID` form-field pairing | 5 / 13 |
| 1100015 | flowbit setter `p2s_bigpost` (state only, no alert) | – / – |

¹ `threshold limit 1/60s by_dst` — a 3-probe scanner burst yields one alert.

Counts are from the CI-validated baseline (Suricata 7.0.10). Synthetic-pcap
counts are deterministic; real-CLI counts vary by ±1–2 per run (the toolkit
jitters timing and retries stages) — the CI suite asserts minimums, not exact
equality.

</details>

**False-positive guards.** The benign regression set (normal browser uploads
using the *legitimate* `session.upload_progress` feature, normal PHPSESSID
cookies, application-level OOM fatals with real file paths, 11MB uploads
without upload-progress) produces **zero** alerts. Discriminators are
documented per-SID in [`docs/SIGNALS.md`](docs/SIGNALS.md).

---

## MITRE ATT&CK mapping

Every rule carries native `mitre_attack_phase` metadata (ET-Open convention),
so SIEM/EDR correlation engines can consume the mappings directly:

| Tier | Techniques |
|---|---|
| A — exploit chain (1100001–1100006) | [T1190](https://attack.mitre.org/techniques/T1190/) Exploit Public-Facing Application; T1059.004 Unix Shell on the forge requests (stage-3 carries the `system()` payload) |
| B — active scanner (1100007–1100010, 1100014) | [T1595.002](https://attack.mitre.org/techniques/T1595/002/) Vulnerability Scanning |
| C — target state (1100012–1100013) | T1190 (server-side evidence of exploitation) |

Per-SID mappings are in the [SID registry](docs/SIGNALS.md#sid-registry).

---

## How the harness works

```
┌───────────────────────────────────────────────────────────────────────┐
│  synthetic suite                                                      │
│                                                                       │
│  lib.chain / lib.oomprobe (upstream, pinned commit)                   │
│        │  byte-exact request builders                                 │
│        ▼                                                              │
│  gen_traffic.py ──► attack.pcap ──┐   benign.pcap ──┐                 │
│                                   ▼                 ▼                │
│                     suricata -r (offline, 7.0.10)                     │
│                                   │                 │                │
│                                   ▼                 ▼                │
│                     assert 13/13 SIDs      assert 0 alerts           │
└───────────────────────────────────────────────────────────────────────┘

┌───────────────────────────────────────────────────────────────────────┐
│  real-tool end-to-end                                                 │
│                                                                       │
│  php2shell CLI (detect → preflight → exploit)                         │
│        │  plain HTTP, wire-exact                                      │
│        ▼                                                              │
│  mock_target.py (vulnerable-state replica: OOM-fatal parser,          │
│                  heap-leak cookies, proof channel)                    │
│        ▼                                                              │
│  tee_proxy.py ──► recorded wire bytes ──► attack-real.pcap ──►        │
│  suricata -r ──► assert every alert SID ≥ 1                           │
└───────────────────────────────────────────────────────────────────────┘
```

The synthetic path guarantees *byte-identical* traffic (it imports the
upstream builders); the real-tool path proves the whole pipeline against the
actual CLI — including retry loops, jittered timing, and the final
`PROOF: uid=33(www-data)` in the mock.

---

## Quick start

Requirements: `python3` (≥3.10), `git`, Suricata **≥ 7.0.10**.

```bash
# 1) fetch the upstream reference (read-only consumer, used to build pcaps)
git clone --depth 1 https://github.com/aarsaputra/php2shell.git /tmp/php2shell

# 2) synthetic + benign regression (fast, ~30s)
P2S_REPO=/tmp/php2shell python3 lab/test_matrix.py --skip-real

# 3) full suite incl. the real CLI end-to-end
python3 -m venv /tmp/php2shell/.venv
/tmp/php2shell/.venv/bin/pip install -r /tmp/php2shell/requirements.txt
P2S_REPO=/tmp/php2shell python3 lab/test_matrix.py
```

Expected:

```
[attack] alerts-by-sid: {1100001: 3, 1100002: 3, ...} total: 28
[benign] alerts-by-sid: {} total: 0
[PASS] test_matrix: attack coverage complete, benign clean, real-tool end-to-end ok
```

Environment knobs: `SURICATA_BIN`, `SURICATA_CONF`, `P2S_REPO`, `P2S_PY`,
`OUT_DIR` — see the headers of the `lab/` scripts.

---

## Production deployment

Install the rules and apply the mandatory libhtp tuning:

```yaml
# suricata.yaml -> stream -> reassembly -> libhtp
request-body-limit: 32mb      # default 100kb truncates 12MB bodies -> body rules die
response-body-limit: 1mb
```

**Why this matters:** the chain deliberately sends 10–20MB single multipart
fields; with the stock 100KB body limit the request-body rules silently
stop matching while headers still pass — the most common hidden
false-negative for this exploit class.

Sensor placement and IPS-drop guidance (which SIDs are safe to `drop`
inline, TLS termination points, version caveats): [`docs/TUNING.md`](docs/TUNING.md).
Per-signal provenance with upstream source references and FP guards:
[`docs/SIGNALS.md`](docs/SIGNALS.md).

### Version compatibility

Validated against **Suricata 7.0.10** (CI builds this exact version from
the official tarball). On **7.0.3** (Ubuntu 24.04 default) the
response-side cookie-leak rules (1100004/1100005) do not fire due to
libhtp header-normalization and `distance` semantics differences; all
request-side rules and 1100012/1100013 work on both. Details in
[`docs/TUNING.md`](docs/TUNING.md).

---

## Repository layout

```
rules/php2shell.rules    14 SIDs (13 alert rules + 1 flowbit setter)
lab/
  gen_traffic.py         byte-exact pcap generator (imports upstream builders)
  pcap_build.py          pure-python pcap writer (correct TCP/IP checksums)
  mock_target.py         behavioral replica of a vulnerable PHP 8.4.26 target
  tee_proxy.py           per-connection wire recorder (real CLI -> pcap)
  run_real.py            end-to-end pipeline: real CLI -> pcap -> Suricata
  mini_test.py           bisection fixtures (leak cookies, OOM-fatal variants)
  make_lab_config.py     lab suricata.yaml derived from the system default
  test_matrix.py         regression suite (exit-code assertions)
docs/
  SIGNALS.md             SID registry: upstream provenance + FP guards
  TUNING.md              production tuning, IPS guidance, engine lessons
.github/workflows/
  test.yml               CI: both suites on every push
  diag.yml               manual dispatch: rule-variant diagnostics
```

---

## CI

The `rules-regression` workflow runs on every push and pull request:

1. **synthetic-suite** — generates byte-exact exploit pcaps and the benign
   regression set, runs offline Suricata, asserts the alert matrix
   (attack ≥ expected per-SID, benign = 0).
2. **real-tool-e2e** — prepares the upstream toolkit in a venv, runs the
   real CLI against the mock target until `PROOF`, converts the recorded
   wire bytes to a pcap, asserts every alert SID fired at least once.

If the toolkit's wire format changes, or a rule starts false-positive-ing,
CI fails before any human has to read a log.

`diag.yml` is a manual-dispatch diagnostic harness (rule-variant bisection
against the runner's Suricata) kept for future engine-version debugging.

---

## Provenance & references

- Toolkit under detection: [`aarsaputra/php2shell`](https://github.com/aarsaputra/php2shell)
  (CI pins commit `1ba7168`, consumed read-only)
- Original vulnerability research: [Wiz Research — php2shell](https://www.wiz.io/blog/php2shell-php-rce)
- Active-detection methodology: [`assetnote/php2shell-scanner`](https://github.com/assetnote/php2shell-scanner)
  (graded 1/8/20 MiB probes, fatal-in-parser / empty-500 differential signals)
- PHP advisories: GHSA-w8hw-w9fx-j79w (CVE-2026-109618),
  GHSA-6wmf-4rv5-p3rp (CVE-2026-109619); fixed in 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12

## Security policy

This repository contains **detection signatures and test fixtures only** —
no exploit code is distributed here beyond what the upstream toolkit
publishes, and the harness never targets non-local addresses. If you
believe a rule causes operational impact (false positives in production),
open an issue with the `eve.json` record and a benign traffic description.

## License

[MIT](LICENSE). The signature rules encode observable facts about public
toolkit behavior and are not derivative of the upstream codebase.
