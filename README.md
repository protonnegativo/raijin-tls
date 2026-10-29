# ⚡ Raijin TLS

[![CI](https://github.com/protonnegativo/raijin-tls/actions/workflows/ci.yml/badge.svg)](https://github.com/protonnegativo/raijin-tls/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/protonnegativo/raijin-tls)](https://github.com/protonnegativo/raijin-tls/releases/latest)
[![License: MIT](https://img.shields.io/github/license/protonnegativo/raijin-tls)](LICENSE)
[![Go Reference](https://pkg.go.dev/badge/github.com/protonnegativo/raijin-tls.svg)](https://pkg.go.dev/github.com/protonnegativo/raijin-tls)
[![Go Report Card](https://goreportcard.com/badge/github.com/protonnegativo/raijin-tls)](https://goreportcard.com/report/github.com/protonnegativo/raijin-tls)

**tlsx for AI agents: weak protocols, weak ciphers and certificate issues, grouped by issue, with every endpoint's certificate and TLS configuration collapsed.**

`raijin-tls` is a tool of **Raijin**, an arsenal of offensive security tools built for AI agents. It runs [tlsx](https://github.com/projectdiscovery/tlsx) with the certificate checks and the version and cipher enumeration turned on, and returns the **Raijin Schema**: one compact JSON where every issue (expired, self-signed, mismatched, TLS 1.0, a weak cipher...) is one ranked finding that lists every affected `host:port`, endpoints with the same certificate share one group, endpoints with the same TLS configuration share another, and anything it had to cut is counted.

## Why not just run tlsx?

It is built for people and pipelines. An agent pays for every byte it reads. tlsx's JSON is one line per endpoint that repeats the whole certificate (subject, issuer, organizations, three fingerprints, serial) and the full cipher list of every protocol version, where each suite is written twice, once by its IANA name and once by its OpenSSL name. Its text output is shorter, but it is the same cipher lists on one line per endpoint and version, and the same certificate fingerprint on every endpoint that serves it.

Here are the same endpoints, with the same certificates, versions and ciphers, read by an agent (tokens, `o200k_base`):

```
Noisy: 15 endpoints, 2 certificates, 2 TLS configurations, no issues
  raijin-tls      ██▎                       949 tokens
  tlsx text       ████████████            5,054 tokens
  tlsx JSON       ████████████████████    8,420 tokens

Findings: 11 endpoints, 6 certificates, 8 findings (2 high, 3 medium, 2 low, 1 info)
  raijin-tls      ██████▏                 2,019 tokens
  tlsx text       ████████████▍           4,037 tokens
  tlsx JSON       ████████████████████    6,523 tokens
```

raijin-tls reads **8.9×** fewer tokens than tlsx's JSON on the noisy run and **3.2×** fewer on the findings run. Each scenario's bars are drawn to scale against the JSON.

- **Nothing is lost.** Every endpoint tlsx reported is in the output, with its negotiated version and cipher, every version and cipher it accepts, and its certificate (fingerprint, subject, SANs, issuer, validity). `bench/verify.py` checked 26 tlsx results in the two scenarios, attribute by attribute, and none were missing.
- **The real problems come first.** An expired certificate and SSLv3 are high, a self-signed or mismatched certificate and TLS 1.0 are medium, CBC on old protocols and a certificate about to expire are low. Each is one finding with every endpoint that has it.
- **Noise is one line.** In the noisy run, the 12 endpoints with the same certificate are one group and the 12 with the same versions and 13 ciphers are another, not 12 copies of each.
- **Output is bounded.** On a huge scan, `--max-bytes` cuts the least important data first and counts every cut.
- **Details are one file away.** tlsx's JSONL is saved to a file, and its path is in `raw`. It holds the serials, the organizations, every fingerprint, the OpenSSL cipher names and tlsx's full errors, costs no tokens until the agent opens it, and replays with `--input`.

Against tlsx's text output (same probes), raijin-tls is **5.3×** smaller on the noisy run and **2.0×** smaller on the findings run, where most endpoints have their own certificate. The text output also has no grouping, no ranking, no SANs, no issuer and no expiry dates. Full method and numbers are in [BENCHMARK.md](BENCHMARK.md), and `bench/run.sh` reproduces them.

## Install

```bash
go install github.com/protonnegativo/raijin-tls/cmd/raijin-tls@latest
```

This installs the latest release.

You also need `tlsx` on `PATH` (`go install github.com/projectdiscovery/tlsx/cmd/tlsx@latest`), or pass `--tlsx <path>`.

**Versions.** A release is tagged automatically on every change and on every passing engine update. `raijin-tls --version` shows the release and the tested engine versions (`raijin-tls v0.1.0 (tested with tlsx 1.4.0)`). `raijin-mcp update` updates every Raijin tool at once.

## Usage

```bash
raijin-tls --scope scope.txt                              # scan every host the scope names
raijin-tls --scope scope.txt -u app.example.com
raijin-tls --scope scope.txt -l hosts.txt -p 443,8443 --max-items 20
raijin-tls --scope scope.txt -u 10.0.0.0/24 --no-enum      # negotiated version and cipher only, much faster
raijin-tls --scope scope.txt --input tlsx.jsonl            # replay a saved run, nothing is sent
raijin-tls --scope scope.txt -l hosts.txt --state run.json # mark findings that are new since last run
raijin-tls ... -- -re -jarm                                 # anything after -- goes to tlsx
```

`--scope` is required. One rule per line:

```
example.com
*.example.com
10.0.0.0/24
!10.0.0.13
```

With no `-u`, `-l` or `--input`, raijin-tls scans what the scope names: every domain, every IP, and every address of ranges up to a /24, minus exclusions. Each host goes to tlsx as it is, so tlsx connects to port 443 unless `-p` says otherwise. A wildcard names no host and a larger range is too big to sweep blindly, so for each one `next` gives the command that enumerates it first (`raijin-subs` or `raijin-ports`).

Targets outside the scope are dropped before tlsx runs. A CIDR target is expanded (up to a /16) and every address is checked on its own, so an exclusion inside a range is never scanned. Results for hosts outside the scope are dropped too. Both are counted in `omitted.out_of_scope`.

`--input` reads tlsx JSONL (`tlsx -json`), like the `raw` file; it can be given more than once. A replay never runs tlsx, and it is checked with the same rules: a run without `-ve -ce` has only the negotiated version and cipher.

**Active scan.** tlsx opens TLS connections to every target, and the cipher enumeration opens one per version and cipher. Scan only what you are authorized to test. Revocation (`-re`) is off by default because it queries the CA's OCSP and CRL servers, which are not the target.

## Output

```json
{
  "schema_version": 1,
  "tool": "raijin-tls",
  "version": "v0.1.0",
  "target": "bench/fixtures/findings/raw.jsonl",
  "summary": "11 endpoints, 6 certificates, 8 findings (2 high, 3 medium, 2 low, 1 info), 10 groups, 1 no TLS",
  "findings": [
    {"id": "expired-cert", "title": "Expired certificate", "severity": "high",
     "locations": ["localhost:19281 [expired 2025-01-01]", "localhost:19288 [expired 2025-01-01]"]},
    {"id": "revoked-cert", "title": "Revoked certificate", "severity": "high",
     "locations": ["localhost:19281", "localhost:19288"]},
    {"id": "old-tls", "title": "TLS 1.0 or 1.1 enabled", "severity": "medium",
     "locations": ["localhost:19284 [tls10, tls11]", "localhost:19289 [tls10, tls11]"]},
    {"id": "self-signed", "title": "Self-signed certificate", "severity": "medium",
     "locations": ["localhost:19282", "localhost:19289"]},
    {"id": "mismatched", "title": "Certificate does not match the host name", "severity": "medium",
     "locations": ["localhost:19283 [other.example]"]},
    {"id": "cbc-old-protocol", "title": "CBC ciphers on SSLv3, TLS 1.0 or 1.1", "severity": "low",
     "locations": ["localhost:19284 [tls10, tls11]", "localhost:19289 [tls10, tls11]"]},
    {"id": "expiring-soon", "title": "Certificate expires within 30 days", "severity": "low",
     "locations": ["localhost:19285 [2026-11-03, 9 days]"]},
    {"id": "wildcard-cert", "title": "Wildcard certificate", "severity": "info",
     "locations": ["localhost:19286 [*.lab.test]"]}
  ],
  "groups": [
    {
      "id": "cert-e759a7bf",
      "cert": {
        "sha256": "e759a7bfa60c143b7e3f092286324c95d859bbd47a6ee6ec3423b11ea0f93ffd",
        "subject": "O=Raijin Lab, CN=localhost",
        "issuer": "CN=Raijin Lab CA, O=Raijin Lab",
        "not_before": "2026-10-24T23:57:03Z",
        "not_after": "2027-10-24T23:57:03Z"
      },
      "ip": "127.0.0.1",
      "locations": ["localhost:19280", "localhost:19284", "localhost:19287"]
    },
    {
      "id": "cert-d531468a",
      "cert": {
        "sha256": "d531468a8680c8923f1ef0d7d5ce077e39173f8b972758a865a38532d80bf340",
        "subject": "O=Raijin Lab, CN=*.lab.test",
        "san": ["*.lab.test", "localhost"],
        "issuer": "CN=Raijin Lab CA, O=Raijin Lab",
        "not_before": "2026-10-24T23:57:03Z",
        "not_after": "2027-10-24T23:57:03Z"
      },
      "ip": "127.0.0.1",
      "locations": ["localhost:19286"]
    },
    {
      "id": "tls-93182a85",
      "version": "tls13",
      "cipher": "TLS_AES_256_GCM_SHA384",
      "versions": ["tls10", "tls11", "tls12", "tls13"],
      "ciphers": {
        "tls10,tls11": ["TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA", "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA", "TLS_RSA_WITH_AES_128_CBC_SHA", "TLS_RSA_WITH_AES_256_CBC_SHA"],
        "tls12": ["TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA", "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256", "..."]
      },
      "ip": "127.0.0.1",
      "locations": ["localhost:19284", "localhost:19289"]
    },
    {"id": "failed-9ac8a83d", "error": "port closed or filtered", "locations": ["localhost:19298"]}
  ]
}
```

That is the real findings run from the benchmark (`--input` on the saved tlsx output of the local lab), pretty-printed here with short arrays kept on one line. Three things are shortened: 4 of the 6 certificate groups and 2 of the 3 configuration groups are left out, and the `tls12` list (13 suites) is cut after two. The tool writes it as one line. `revoked-cert` is what tlsx 1.2.2 reports: it sets `revoked` on the expired certificates of the lab (signed by a local CA with no OCSP or CRL) even without `-re`, and raijin-tls keeps what tlsx found.

**Nothing tlsx found is dropped silently.** Every endpoint is in exactly one certificate group and one configuration group (or one failed group), and every issue tlsx flagged on it is in a finding. Only exact repeats collapse, and they are counted in `omitted.duplicates`.

What the reducer does:

- **One result per endpoint**: tlsx's host, port, IP and SNI. The location is `host:port` (`[2001:db8::5]:443` for IPv6), with ` sni=<name>` when tlsx sent an SNI that is not the host, and the IP in brackets when tlsx reached the same `host:port` on several IPs (`-sa`). Two lines that differ only in their timestamp are one result.
- **Certificate groups**: endpoints with the same certificate share one `cert-<fingerprint>` group: the SHA-256 fingerprint (SHA-1 or MD5 when tlsx wrote no SHA-256), the subject and issuer DNs, the SANs, `not_before` and `not_after`.
- **Configuration groups**: endpoints with the same negotiated version and cipher, the same accepted versions (`versions`, oldest first) and the same accepted ciphers share one `tls-<hash>` group. `ciphers` lists the suites by version, with versions that accept exactly the same list joined (`"tls10,tls11"`); tlsx enumerates TLS 1.3 by version only, so it is in `versions` but not in `ciphers`. `client_cert`, `jarm` and `ja3s` are written when tlsx found them.
- **Cipher names**: tlsx enumerates with Go's TLS stack and with OpenSSL and writes each suite twice (`TLS_RSA_WITH_AES_128_CBC_SHA` and `AES128-SHA`). Every suite is written once, by its IANA name, using the table in `internal/reduce/ciphers.go` (OpenSSL 3.0.13's `-stdname` list plus the legacy suites). A name not in the table is written as tlsx wrote it.
- **Failed groups**: a target that did not answer TLS is in a `failed-<hash>` group with tlsx's first error cause (`port closed or filtered`); tlsx repeats its error once per retry.
- **Findings** are the issues, one per rule, each listing every endpoint with it and what was found there in brackets. Each rule has a fixed severity:

  | ID | Severity | Rule (and what is in the brackets) |
  |---|---|---|
  | `expired-cert` | high | tlsx flagged the certificate expired, or `not_after` is before the result's timestamp `[expired <date>]` |
  | `revoked-cert` | high | tlsx flagged it revoked (`-re`) |
  | `sslv3` | high | SSLv3 (or SSLv2) accepted `[ssl30]` |
  | `insecure-cipher` | high | a suite with NULL encryption, export keys, anonymous key exchange (`anon`, `ADH`, `AECDH`), RC4, single DES or MD5, or one tlsx typed `insecure` `[the suites]` |
  | `self-signed` | medium | tlsx flagged the certificate self-signed |
  | `mismatched` | medium | tlsx flagged that the certificate does not match the host `[the certificate's names]` |
  | `untrusted` | medium | tlsx wrote `untrusted` (tlsx 1.2.2 wrote none in the lab, even with `-un`) |
  | `old-tls` | medium | TLS 1.0 or 1.1 accepted `[tls10, tls11]` |
  | `weak-cipher` | medium | a 64-bit block cipher (3DES, IDEA, RC2: Sweet32), or one tlsx typed `weak` `[the suites]` |
  | `cbc-old-protocol` | low | a CBC suite accepted on SSLv3, TLS 1.0 or 1.1 (BEAST, POODLE, Lucky13); there every suite but RC4 and NULL is CBC `[the versions]` |
  | `expiring-soon` | low | `not_after` is less than 30 days after the result's timestamp `[<date>, <n> days]` |
  | `wildcard-cert` | info | tlsx flagged a wildcard certificate `[the wildcard names]` |

  The ciphers checked are every suite tlsx enumerated plus the negotiated one, so `--no-enum` still checks what the server picked. Expiry is checked against the timestamp tlsx wrote, so a replay gives the same findings as the run.
- **Ranking:** findings by severity, then confidence, then the number of locations, then `id`. Groups: certificates, then configurations, then failures, each by the number of locations, then `id`. The same input always gives the same order.
- **`id`** is the rule for a finding, so the same issue has the same `id` in every run. A certificate group is `cert-` and the start of the fingerprint; a configuration or failed group is `tls-` or `failed-` and a short hash of what it has in common.
- **`ip`** is written once on a group when every location in it resolved to the same address and the host is a name; otherwise each name gets its IP in brackets in that group's locations (`app.example.com:443 [10.0.0.5]`).
- **`raw`** is tlsx's JSONL, saved as it came. It holds the serials, organizations, every fingerprint, the OpenSSL cipher names, the TLS stack tlsx used and its full errors; reading it costs no tokens until the agent opens it, and `--input` replays it. `--raw <file>` picks the path.
- **Budget:** `--max-bytes` (32,000 by default) keeps the output bounded on huge scans. It cuts in this order until the JSON fits:
  1. group locations (the certificates and configurations stay);
  2. groups;
  3. the locations of the lowest-ranked findings, each keeping one location plus its `count`;
  4. the lowest-ranked findings.

  Every cut is counted in `omitted`, `budget.truncated` is set, and `next` points to the raw file. `--max-items` caps the number of findings (0, the default, keeps all).
- **`schema_version`** is the first field (currently `1`), so a reader can check the shape it parses.
- **Errors** say what to try next. An invalid scope file gives `errors` with `kind: "scope"`, one per invalid line (`line 3: ...`), and scans nothing.
- **Exit codes:** 0 is ok; 1 is a usage error (bad flag, missing `--scope`, no target in scope), with the message on stderr and nothing on stdout; 2 is a structured error with the JSON on stdout (invalid scope, a scope that names no single host, tlsx not found), which an agent tells apart by `errors[].kind`, or by `next` when there is no error.

Fields an agent can rebuild are left out to save tokens:

- `san` when it is just the subject CN; `versions` and `ciphers` when tlsx did not enumerate them.
- `count` appears only when the budget cut `locations`.
- `confidence` appears only when it is not `matched`.
- `omitted`, `errors` and `next` appear only when they are not empty.
- `budget` appears only when something was cut.

The JSON is compact (one line) by default because indentation costs 31% to 32% more tokens in the benchmark; `--pretty` indents it. `--format table` prints a short human view of the same result; it lists finding locations but only counts group locations.

The Raijin banner is **off by default**, so normal runs stay small. `--banner` prints it to **stderr** (never stdout, so the JSON is untouched), with the version taken from the binary. Colors are disabled when `NO_COLOR` is set or stderr is not a terminal.

## Flags

| Flag | Default | |
|---|---|---|
| `--scope` | (required) | scope file |
| `-u` / `-l` / `--input` | every host the scope names | hosts, `host:port`s, IPs or CIDRs, comma-separated (repeatable) / target file / existing tlsx JSONL (repeatable) |
| `-p` | tlsx's 443 | tlsx `-p`, comma-separated |
| `--no-enum` | false | do not enumerate versions and ciphers (`-ve -ce`); only check what is negotiated |
| `--timeout`, `--threads` | | tlsx `-timeout` (seconds) / `-c` |
| `--max-items` | 0 | max findings (0 keeps all) |
| `--max-bytes` | 32000 | max JSON size; cuts are counted in `omitted` |
| `--raw` | temp file | where to save tlsx's JSONL |
| `--state` | | state file for new-since-last-run |
| `--format` | json | `json` or `table` |
| `--pretty` | false | indent the JSON |
| `--tlsx` | tlsx | path to the binary |
| `--banner` | false | print the banner to stderr |

## Engine versions

The tested tlsx version is in `engines.json` (embedded in the binary). raijin-tls adds an `engine_version` error when the installed tlsx has another major version or is older, and an `engine_format` error when tlsx's lines lack the fields it reads (`host`, `port`, and `tls_version` or `error`); neither stops the run. A weekly GitHub Actions job runs the live benchmark with the latest tlsx and commits the bump to `engines.json` and tags a release when it passes, or an `engine-drift` issue when it breaks. The runner's OpenSSL (Ubuntu 24.04, 3.0) still allows TLS 1.0 and 1.1 at security level 0, which the lab's legacy endpoints need; if a future runner drops them, those endpoints fail the handshake and verify still checks tlsx's own output against raijin-tls.

## Development

```bash
go test ./...
go vet ./...
```

The only dependency is [raijin-core](https://github.com/protonnegativo/raijin-core) (scope, schema envelope and state); everything else is the standard library. tlsx runs as a subprocess with `-json -silent -nc -duc -ex -ss -mm -wc -tps -ve -ce`, so the binary stays small and the engine can be updated on its own. The CLI tests run the live path offline with a small fake tlsx; `testdata/sample.jsonl` is a synthetic run with what the lab cannot produce (SSLv3, RC4 and 3DES, an untrusted certificate, IPv6, an SNI that is not the host, one host on several IPs, an out-of-scope host and a repeated line), and the unit tests cover the NULL, export, anonymous, IDEA and MD5 suites. `bench/lab.py` and `bench/certs.sh` are the local lab of the benchmark: TLS servers on 127.0.0.1 with certificates generated by openssl (a lab CA, expired, self-signed, mismatched, expiring and wildcard certificates) and a legacy server that accepts TLS 1.0.

## Responsible use

Only scan hosts you are authorized to test. raijin-tls connects to every target: the scope is required and is checked before anything is sent.
