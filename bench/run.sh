#!/usr/bin/env bash
# Reproducible token benchmark: tlsx output vs raijin-tls output on the same TLS endpoints.
#
# usage: bench/run.sh [workdir]
#        LIVE=1 bench/run.sh [workdir]   start the local lab, rescan it and refresh bench/fixtures first
# needs: go, python3 with tiktoken (pip install tiktoken); LIVE=1 also needs tlsx and openssl
# optional: ANTHROPIC_API_KEY + pip install anthropic for exact Claude token counts
# env: PY=<python with tiktoken>, TLSX=<path>
#
# Safety: LIVE=1 scans only the lab it starts itself (bench/lab.py) on 127.0.0.1, ports 19250-19299,
# with certificates it generates (bench/certs.sh) in the workdir. It stops the lab when it exits.
set -euo pipefail

W=${1:-$(mktemp -d)}
HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$HERE/.." && pwd)
PY=${PY:-python3}
TLSX=${TLSX:-tlsx}
mkdir -p "$W"
echo "workdir: $W"

# Lab: one python process with one TLS server per port on 127.0.0.1 (see lab.py for the kinds).
# noisy:    14 endpoints behind one setup: 10 with the same certificate and TLS 1.2 + 1.3, 2 with a
#           second certificate, 2 with the first certificate and TLS 1.2 only, and 1 closed port.
# findings: one endpoint per issue: a good one, expired (twice, the same certificate), self-signed,
#           a mismatched name, TLS 1.0 and 1.1 with CBC ciphers, expiring in 10 days, a wildcard, TLS
#           1.2 only, self-signed with TLS 1.0, and 1 closed port.
noisy=()
for p in $(seq 19250 19259); do noisy+=("$p=good"); done
noisy+=(19260=app 19261=app 19262=good+tls12 19263=good+tls12)
noisy_closed=19297
findings=(19280=good 19281=expired 19282=self 19283=mismatch 19284=good+legacy 19285=soon 19286=wildcard
  19287=good+tls12 19288=expired 19289=self+legacy)
findings_closed=19298
printf 'localhost\n' > "$W/scope.txt"

(cd "$ROOT" && go build -o "$W/raijin-tls" ./cmd/raijin-tls)

if [ "${LIVE:-}" = 1 ]; then
  for spec in "${noisy[@]}" "${findings[@]}" $noisy_closed= $findings_closed=; do
    port=${spec%%=*}
    if ss -ltn | grep -q ":$port "; then echo "port $port is busy; free it first" >&2; exit 1; fi
  done
  bash "$HERE/certs.sh" "$W/certs" > /dev/null
  python3 "$HERE/lab.py" "$W/certs" "${noisy[@]}" "${findings[@]}" > "$W/lab.log" 2>&1 &
  echo $! > "$W/pids"
  trap '[ -f "$W/pids" ] && xargs kill < "$W/pids" 2>/dev/null || true' EXIT
  sleep 2
  # Cipher enumeration is CPU-bound (tlsx runs openssl once per cipher), so the four scans run at once.
  for name in noisy findings; do
    f=$HERE/fixtures/$name
    mkdir -p "$f"
    eval 'specs=("${'$name'[@]}")'
    eval 'closed=$'$name'_closed'
    { for spec in "${specs[@]}" "$closed="; do echo "localhost:${spec%%=*}"; done; } > "$W/$name.targets"
    # raijin-tls runs tlsx (-json -ex -ss -mm -wc -tps -ve -ce) and saves its JSONL as raw: that file is
    # the fixture and the JSON baseline.
    "$W/raijin-tls" --tlsx "$TLSX" --scope "$W/scope.txt" -l "$W/$name.targets" --raw "$f/raw.jsonl" > "$W/$name.live.json" &
    # tlsx's text output with the same probes, as an agent would read it.
    "$TLSX" -l "$W/$name.targets" -silent -nc -duc -ex -ss -mm -wc -tps -ve -ce -tv -cipher -hash sha256 -so -se < /dev/null > "$f/text.txt" 2>&1 &
  done
  wait $(jobs -p | grep -v "$(cat "$W/pids")")
fi

scenario() {
  local name=$1
  local f=$HERE/fixtures/$name o=$W/$name
  mkdir -p "$o"
  # raijin-tls replays raw with --input, so every row sees the same endpoints.
  (cd "$ROOT" && "$W/raijin-tls" --scope "$W/scope.txt" --input "bench/fixtures/$name/raw.jsonl") > "$o/raijin.json"
  (cd "$ROOT" && "$W/raijin-tls" --scope "$W/scope.txt" --input "bench/fixtures/$name/raw.jsonl" --pretty) > "$o/raijin_pretty.json"
  (cd "$ROOT" && "$W/raijin-tls" --scope "$W/scope.txt" --input "bench/fixtures/$name/raw.jsonl" --format table) > "$o/raijin_table.txt"
  echo; echo "## $name: $(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["summary"])' "$o/raijin.json")"; echo
  python3 "$HERE/verify.py" "$f/raw.jsonl" "$o/raijin.json" "$W/scope.txt"
  "$PY" "$HERE/count_tokens.py" \
    "tlsx -json=$f/raw.jsonl" \
    "tlsx text=$f/text.txt" \
    "raijin-tls JSON (default)=$o/raijin.json" \
    "raijin-tls --pretty=$o/raijin_pretty.json" \
    "raijin-tls --format table=$o/raijin_table.txt"
}

scenario noisy
scenario findings
