# Tuning & operations

## Mandatory tuning

```yaml
# suricata.yaml -> stream -> reassembly -> libhtp:
request-body-limit: 32mb     # default 100kb truncates 12MB bodies -> body rules die
response-body-limit: 1mb
```

Without this patch, any `http.request_body` rule for payloads ≥1MB will not
fire — large requests still pass header inspection but their bodies are
never scanned. This is the most common hidden false-negative behind Suricata
defaults for this particular exploit class, because the chain deliberately
sends 10–20MB single multipart fields.

## Sensor placement

- **Cleartext HTTP**: rules work as-is, no extra configuration.
- **HTTPS**: rules match on the HTTP plaintext — the sensor must see it
  (terminate TLS at the LB/WAF, or mirror traffic after TLS termination).
  The toolkit's JA3 impersonation is irrelevant here: these rules are not
  TLS fingerprints, they are body/behavior signatures.
- **mod_php prefork**: the full chain needs the worker to die (SIGABRT),
  but the *requests themselves* are ordinary HTTP — detection lands long
  before damage occurs.

## IPS (inline) — what is safe to drop

| SIDs | Drop? | Rationale |
|---|---|---|
| 1100001, 1100002, 1100003, 1100007, 1100008, 1100009 | **yes** | request-side, exotic byte literals, zero FP in regression |
| 1100010 | yes (noted) | quoted single-char boundary ≈ never seen in legit apps |
| 1100006 | yes, with calibration | requires both CL ≥10MB and UP-field; rare-but-possible legit combo |
| 1100004, 1100005 | alert only, no drop | response-side; unique but not request material |
| 1100012 | never drop | server-state signal, useful for triage/IR |
| 1100013 | never drop | cross-flow correlation; 5xx has many innocent causes |

## Engine lessons (Suricata 7.0.10, empirical)

1. **Oversized single multipart field (~>1MB)**: libhtp treats the field as
   a file and `http.request_body` stops fragmenting deep into it (needle
   test: 60KB ✓, 500KB ✓, 3.3MB ✗). Multi-content rules spanning MB-scale
   offsets silently become FALSE-NEGATIVE. Use a same-packet flowbit pair
   with the setter loaded first (pattern 1100015 → 1100006).
2. **`relative;` is a Snort keyword, not Suricata.** `distance`/`within`
   are already implicitly relative to the previous content match. A stray
   `relative;` keyword makes the whole rule fail to parse (and depending on
   the run mode, may take siblings down with it). Always validate rule files
   with `suricata -T -c ... -S ...`.
3. **`content` + non-`R` `pcre` in the SAME sticky buffer** did not match
   ever on 7.0.10, while each piece matched alone. Splitter options:
   plain-content only, or a flowbit pair.
4. **fast.log flushes late** for sub-second offline runs: never treat an
   absent fast.log line as proof of "no alert". Read `counters: Alerts:` in
   suricata.log or parse eve.json.
5. **Fixtures must be byte-exact**: a one-character mistake (a missing `%`
   in percent-encoding) made cookie rules look dead while the rules were
   fine and the traffic was wrong. If a rule doesn't fire: hexdump the wire
   first, suspect the engine last.

## CI

`.github/workflows/test.yml` runs on every push:

1. `synthetic-suite`: byte-exact pcap generation + benign regression pool →
   asserts every SID fires at least its matrix minimum and benign = 0.
2. `real-tool-e2e`: upstream venv prepared, then `run_real.py` (real CLI
   driving the mock target until PROOF) → every alert SID fires ≥1.

If the toolkit's wire format ever changes, or a rule starts to false-positive,
this suite is what fails first — the rules and the tests keep each other
honest.

## Rootless operation

For rule verification without installing anything: extract Suricata `.deb`s
into a rootfs and run offline pcap mode (`-r file.pcap`); mind glibc/libpcap
compatibility. For production sensors, use the distro's `suricata` package.
