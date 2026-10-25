# Token benchmark: tlsx vs raijin-tls

How many tokens does an AI agent spend reading the result of a TLS scan with version and cipher enumeration, and does it lose anything? This benchmark scans a local lab with tlsx, counts the tokens in each output shape, and checks that every endpoint, certificate, version, cipher and issue flag tlsx reported is in the raijin-tls output.

Reproduce from the saved tlsx output: `bench/run.sh`. Start the lab, rescan it and refresh the fixtures first: `LIVE=1 bench/run.sh` (needs tlsx and openssl; it took 2 minutes on a 2-core machine with a load average between 13 and 35; fingerprints, dates and timestamps will differ, the endpoints and issues should not).

## Setup

- **Lab:** `bench/lab.py`, one python process with one TLS server (Python's `ssl`, OpenSSL 3.0.13) per port on 127.0.0.1, ports 19250 to 19299, started by `bench/run.sh` and stopped when it exits. `bench/certs.sh` generates the certificates with openssl into the work directory: a lab CA, and leaves for `localhost` signed by it (valid, expired on 2025-01-01, expiring in 10 days), one for `other.example` only (mismatched), a wildcard (`*.lab.test` and `localhost`) and a self-signed one. The servers accept TLS 1.2 and 1.3; the legacy ones accept TLS 1.0 to 1.3 with every cipher OpenSSL has at security level 0. Nothing outside the machine was scanned. The run was on 2026-10-24.
- **tlsx:** v1.2.2, `-json -silent -nc -duc -ex -ss -mm -wc -tps -ve -ce`, as raijin-tls runs it, on `localhost:<port>` targets.
- **Fixtures:** `bench/fixtures/<scenario>/raw.jsonl` is the `raw` file of the live raijin-tls run: tlsx's JSON lines. `text.txt` is tlsx's text output with the same probes (`-ex -ss -mm -wc -tps -ve -ce -tv -cipher -hash sha256 -so -se`), run at the same time on the same targets. Every row below is computed from these files, so `bench/run.sh` gives the same numbers offline.
- **raijin-tls:** replays `raw.jsonl` with `--input`, so every row sees the same endpoints. Defaults apply: no limit on findings, and `--max-bytes 32000`, which was not reached.
- **Baselines**, as an agent would read tlsx:
  - JSON: `raw.jsonl` itself.
  - Text: tlsx's default output with the same probes. tlsx 1.2.2 writes one line per endpoint (status, organization, version, cipher, flags, serial, SHA-256 fingerprint, then the first enumerated version and its ciphers) and one more line per other enumerated version. It writes nothing for the closed port, and no SANs, issuer or dates (`-san` and `-cn` cannot be combined with the other probes).
- **Tokens:** counted with tiktoken (`o200k_base`). This is a **proxy**, because Claude's tokenizer is not public. `bench/count_tokens.py` also gives exact Claude counts if `ANTHROPIC_API_KEY` is set and the `anthropic` package is installed. `cl100k_base` gives the same ratios.

## Scenario 1: noisy

15 endpoints: 10 with the same certificate and TLS 1.2 + 1.3, 2 with a second certificate (more SANs) and the same configuration, 2 with the first certificate and TLS 1.2 only, and 1 closed port. raijin-tls returned no findings and 5 groups: the 2 certificates (12 and 2 endpoints), the 2 configurations (12 and 2 endpoints), and the closed port.

| Output | Bytes | Tokens | vs. tlsx JSON |
|---|---:|---:|---:|
| tlsx `-json` | 23,065 | 8,420 | 1× |
| tlsx text | 12,196 | 5,054 | 1.7× |
| **raijin-tls JSON (default)** | 2,668 | **927** | **9.1×** |
| raijin-tls `--pretty` | 3,776 | 1,215 | 6.9× |
| raijin-tls `--format table` | 333 | 101 | 83× |

## Scenario 2: findings

11 endpoints: a valid one, expired (twice, the same certificate), self-signed, mismatched, TLS 1.0 and 1.1 with CBC ciphers, expiring in 10 days, a wildcard, TLS 1.2 only, self-signed with TLS 1.0, and 1 closed port. raijin-tls returned 8 findings and 10 groups:

- high: expired certificate (2 endpoints), revoked certificate (the same 2: tlsx 1.2.2 sets `revoked` on these expired certificates of a CA with no OCSP or CRL, without `-re`);
- medium: TLS 1.0 or 1.1 enabled (2), self-signed (2), mismatched (1);
- low: CBC ciphers on TLS 1.0 or 1.1 (2), certificate expiring within 30 days (1);
- info: wildcard certificate (1);
- the groups: 6 certificates, 3 configurations (TLS 1.2 + 1.3 on 7 endpoints, TLS 1.0 to 1.3 on 2, TLS 1.2 only on 1) and the closed port.

| Output | Bytes | Tokens | vs. tlsx JSON |
|---|---:|---:|---:|
| tlsx `-json` | 17,890 | 6,523 | 1× |
| tlsx text | 9,757 | 4,037 | 1.6× |
| **raijin-tls JSON (default)** | 5,646 | **1,997** | **3.3×** |
| raijin-tls `--pretty` | 7,966 | 2,633 | 2.5× |
| raijin-tls `--format table` | 1,508 | 469 | 13.9× |

In both scenarios the raijin-tls JSON includes about 10 tokens for `target`, the path of the replayed fixture. A live run writes the targets there and adds about 18 tokens for `raw`.

**Not in the lab:** SSLv3, RC4, 3DES, NULL, export and anonymous suites, and untrusted certificates. The OpenSSL 3.0.13 build of this machine has no SSLv3, RC4, 3DES, NULL or export suites, and tlsx listed no anonymous suite on the legacy server; tlsx 1.2.2 wrote no `untrusted` field, even with `-un`. TLS 1.0 and 1.1 were possible (security level 0) and are in the lab. The rest is covered by the synthetic fixture `testdata/sample.jsonl` and the unit tests, not by this benchmark.

## Nothing is lost

For each scenario, `bench/verify.py` checks tlsx's output (`raw.jsonl`) against the raijin-tls output. A result is one tlsx line, identified by its `host:port` (plus the SNI when it is not the host, and the IP when the same `host:port` was reached on several IPs). For each result:

- a target that did not answer TLS must be in a failed group with tlsx's first error cause;
- its configuration must be in a `tls-` group with the same negotiated version and cipher, the same enumerated versions, and every (version, cipher) pair tlsx enumerated (OpenSSL names mapped to IANA names with the reducer's table);
- its certificate must be in a `cert-` group with the same SHA-256 fingerprint, subject, SANs, issuer, `not_before` and `not_after`;
- every issue flag tlsx set (`expired`, `self_signed`, `mismatched`, `revoked`, `untrusted`, `wildcard_certificate`) and every SSLv3, TLS 1.0 or TLS 1.1 version it enumerated must be in the locations of the finding for it;
- its IP must be in the location's brackets or the group's `ip`.

Results:

- Scenario 1: 15 tlsx results, **0 missing**.
- Scenario 2: 11 tlsx results, **0 missing**.
- `testdata/sample.jsonl` (with its scope): 12 lines, 10 distinct in scope, 1 out of scope, **0 missing**.

`verify.py` fails when the output loses something (checked by hand on scenario 2, with one location removed from a certificate group, one cipher removed from a configuration, one location removed from a finding and one expiry date changed: 11 missing).

What the JSON leaves out stays in `raw`, which raijin-tls saves to disk: timestamps, serials, the subject and issuer organizations and CNs (they are in the DNs), the MD5 and SHA-1 fingerprints, the OpenSSL names of the suites, tlsx's cipher types, the TLS stack it used (`tls_connection`) and its full error chains.

## Reading the numbers

- **Against tlsx's JSON**, the structured output an agent would parse, raijin-tls uses **9.1×** fewer tokens on the noisy run and **3.3×** fewer on the findings run. tlsx's JSON repeats the whole certificate on every endpoint (DNs, CNs, organizations, three fingerprints, serial), writes every suite twice (IANA and OpenSSL names), and lists the full cipher list of every version on every endpoint.
- **Against tlsx's text output**, the gap depends on the run:
  - noisy: **5.5× smaller** (5,054 → 927);
  - findings: **2.0× smaller** (4,037 → 1,997).

  When many endpoints share a certificate and a configuration, the text repeats both on every endpoint, and raijin-tls writes each once with every endpoint. When most endpoints have their own certificate, raijin-tls pays for one group per certificate and the field names; in exchange the agent gets the SANs, issuer and dates the text leaves out, the issues ranked with a severity, and each suite once.
- **The output stays bounded.** On a scan too big for `--max-bytes`, raijin-tls cuts the least important data first: group locations, then groups, then extra locations of low-ranked findings, then low-ranked findings. Every cut is counted in `omitted`, and `next` points to the raw file. tlsx's output has no upper bound.
