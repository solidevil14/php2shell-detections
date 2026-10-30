#!/usr/bin/env python3
"""test_matrix.py - the regression suite for rules/php2shell.rules.

Runs offline Suricata against byte-exact php2shell exploit traffic and a
benign regression set, then asserts the alert matrix:

  attack.pcap : every expected SID must fire at least min_expected times
  benign.pcap : ZERO alerts allowed

Usage (requires suricata on PATH or SURICATA_BIN env; system config from
/etc/suricata or SURICATA_CONF env):

    python3 lab/test_matrix.py [--skip-real]

Exit codes: 0 = pass, 1 = assertion failure, 2 = environment error.
"""
import argparse
import collections
import json
import os
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)

# expected alert counts on the synthetic attack pcap (Suricata 7.x baseline;
# CI uses >= min so minor engine-version deltas don't false-fail the suite)
EXPECTED_ATTACK_MIN = {
    1100001: 3,   # chain groom boundary Sx17
    1100002: 3,   # chain forge boundary Bx10 + PHPSESSID form field
    1100003: 1,   # worker rotate BNDRY12345
    1100004: 2,   # heap-leak Set-Cookie >=990B
    1100005: 2,   # %7F encoded pointer in leaked cookie
    1100006: 1,   # oversized multipart + upload_progress (flowbit pair)
    1100007: 2,   # nested-62 array key (oomprobe)
    1100008: 1,   # detect probe (----php2shellprobe)
    1100009: 1,   # memprobe P2SMEMPROBE
    1100010: 2,   # quoted single-char boundary "x"
    1100012: 1,   # OOM fatal in multipart parser (threshold-limited)
    1100013: 4,   # worker-abort 5xx differential (xbits correlation)
    1100014: 5,   # upload_progress + PHPSESSID form-field marker
}
EXPECTED_BENIGN = {}   # strictly zero

SURICATA_BIN = os.environ.get("SURICATA_BIN", "suricata")
P2S_REPO = os.environ.get("P2S_REPO", os.path.join(ROOT, "php2shell"))

def sh(cmd, **kw):
    print("[run]", " ".join(map(str, cmd)), flush=True)
    return subprocess.run(cmd, capture_output=True, text=True, **kw)

def ensure_pear():
    """gen_traffic imports upstream lib/chain.py + lib/oomprobe.py so the
    pcap is byte-exact. Pin the upstream commit - see docs/SIGNALS.md."""
    if os.path.isdir(os.path.join(P2S_REPO, "lib")):
        return 0
    r = sh(["git", "clone", "--quiet", "--depth", "1",
            "https://github.com/aarsaputra/php2shell.git", P2S_REPO])
    return r.returncode

def ensure_config(tmp):
    conf = os.environ.get("SURICATA_CONF")
    out = os.path.join(tmp, "suricata-lab.yaml")
    env = dict(os.environ)
    env["LAB_CONF_OUT"] = out
    if conf:
        env["SURICATA_CONF"] = conf
    r = subprocess.run([sys.executable, os.path.join(HERE, "make_lab_config.py")],
                       capture_output=True, text=True, env=env)
    print(r.stdout.strip())
    if r.returncode != 0:
        print(r.stderr, file=sys.stderr)
        return None
    return out

def check_rules(conf):
    r = sh([SURICATA_BIN, "-c", conf, "-S", os.path.join(ROOT, "rules/php2shell.rules"),
            "-T", "-l", os.path.join(tempfile.mkdtemp())])
    if r.returncode != 0:
        print(r.stderr[-2000:], file=sys.stderr)
        return False
    print("[ok] rules parse & conditionally load fine (-T)")
    return True

def run_offline(conf, pcap, outdir):
    os.makedirs(outdir, exist_ok=True)
    r = sh([SURICATA_BIN, "-c", conf, "-S", os.path.join(ROOT, "rules/php2shell.rules"),
            "-r", pcap, "-l", outdir, "-k", "none"])
    counts = collections.Counter()
    eve = os.path.join(outdir, "eve.json")
    if os.path.exists(eve):
        for line in open(eve):
            try:
                e = json.loads(line)
            except ValueError:
                continue
            if e.get("event_type") == "alert":
                counts[e["alert"]["signature_id"]] += 1
    return counts, r

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--skip-real", action="store_true",
                    help="only run the synthetic pcap suite")
    ap.add_argument("--workdir", default=None, help="keep artifacts (pcaps/logs)")
    args = ap.parse_args()

    if shutil.which(SURICATA_BIN) is None and "/" not in SURICATA_BIN:
        print(f"[fail] suricata binary '{SURICATA_BIN}' not on PATH", file=sys.stderr)
        return 2
    if ensure_pear() != 0:
        print("[fail] cannot obtain upstream php2shell clone (P2S_REPO)", file=sys.stderr)
        return 2

    tmp = args.workdir or tempfile.mkdtemp(prefix="p2s-test-")
    print(f"[i] workdir: {tmp}")
    pcap_dir = os.path.join(tmp, "pcaps")
    os.makedirs(pcap_dir, exist_ok=True)

    conf = ensure_config(tmp)
    if not conf or not check_rules(conf):
        return 2

    env = dict(os.environ, P2S_REPO=P2S_REPO, OUT_DIR=pcap_dir)
    r = subprocess.run([sys.executable, os.path.join(HERE, "gen_traffic.py")],
                       capture_output=True, text=True, env=env, cwd=HERE)
    print(r.stdout.strip())
    if r.returncode != 0:
        print(r.stderr, file=sys.stderr)
        return 2

    failures = []

    # attack run
    atk_counts, _ = run_offline(conf, os.path.join(pcap_dir, "attack.pcap"),
                                os.path.join(tmp, "atk"))
    print("[attack] alerts-by-sid:", dict(sorted(atk_counts.items())),
          "total:", sum(atk_counts.values()))
    for sid, minimum in EXPECTED_ATTACK_MIN.items():
        c = atk_counts.get(sid, 0)
        if c < minimum:
            failures.append(f"attack: sid {sid} fired {c}x, expected >= {minimum}")
    unexpected = set(atk_counts) - set(EXPECTED_ATTACK_MIN)
    if unexpected:
        # not fatal (engine may double-count), but flag loudly
        print(f"[warn] attack: unexpected sids fired: {sorted(unexpected)}")

    # benign run
    ben_counts, _ = run_offline(conf, os.path.join(pcap_dir, "benign.pcap"),
                                os.path.join(tmp, "ben"))
    print("[benign] alerts-by-sid:", dict(sorted(ben_counts.items())),
          "total:", sum(ben_counts.values()))
    if sum(ben_counts.values()) != 0:
        failures.append(f"benign: false positive, alerts: {dict(ben_counts)}")

    # real-tool end-to-end (optional but part of 'standar bagus')
    if not args.skip_real:
        real = subprocess.run([sys.executable, os.path.join(HERE, "run_real.py")],
                              capture_output=True, text=True, cwd=HERE,
                              env=dict(os.environ, P2S_REPO=P2S_REPO,
                                       OUT_DIR=os.path.join(tmp, "results"),
                                       SURICATA_BIN=SURICATA_BIN,
                                       SURICATA_CONF=conf))
        tail = "\n".join((real.stdout + real.stderr).splitlines()[-25:])
        print(tail)
        # the real-tool pcap must fire every alert sid at least once
        m = {}
        for line in (real.stdout + real.stderr).splitlines():
            if line.startswith("alerts-by-sid:"):
                m = eval(line.split(":", 1)[1].split("total:")[0].strip())  # noqa: S307
        missing = [sid for sid in EXPECTED_ATTACK_MIN if m.get(sid, 0) < 1]
        if real.returncode != 0:
            failures.append(f"real-tool run failed rc={real.returncode}")
        if missing:
            failures.append(f"real-tool: sids missing: {missing}")

    print()
    if failures:
        print("[FAIL] test_matrix:")
        for f in failures:
            print("  -", f)
        return 1
    print("[PASS] test_matrix: attack coverage complete, benign clean"
          + (", real-tool end-to-end ok" if not args.skip_real else ""))
    return 0

if __name__ == "__main__":
    sys.exit(main())
