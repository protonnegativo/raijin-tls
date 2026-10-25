"""Checks that every tlsx result is in a raijin-tls result.

A result is one tlsx JSON line, identified by its host:port (with the SNI when it is not the host, and
the IP when the same host:port was reached on several IPs). Every attribute tlsx wrote about it must be
in the output:

- a target that did not answer TLS: in a failed group with tlsx's first error cause;
- the TLS configuration: in a tls group with the same negotiated version and cipher, the same enumerated
  versions, and every (version, cipher) pair tlsx enumerated in that group's ciphers (OpenSSL names
  mapped to IANA names with the reducer's table);
- the certificate: in a cert group with the same fingerprint (SHA-256), subject, SANs, issuer,
  not_before and not_after;
- every issue flag tlsx set (expired, self_signed, mismatched, revoked, untrusted, wildcard_certificate)
  and every SSLv3, TLS 1.0 or TLS 1.1 version it enumerated: in the locations of the finding for it;
- the IP: in the location's brackets or the group's ip.

A result whose host is outside the scope (when a scope file is given) must be counted in
omitted.out_of_scope instead.

usage: python verify.py <tlsx.jsonl> <raijin.json> [scope.txt]
"""
import ipaddress, json, os, re, sys

raw, out = sys.argv[1], sys.argv[2]
rules = [l.strip().lower() for l in open(sys.argv[3])] if len(sys.argv) > 3 else []
rules = [r for r in rules if r and not r.startswith("#")]
o = json.load(open(out))
HERE = os.path.dirname(os.path.abspath(__file__))
NAMES = dict(re.findall(r'"([^"]+)":\s+"([^"]+)"', open(os.path.join(HERE, "..", "internal", "reduce", "ciphers.go")).read()))
ORDER = {"ssl20": 0, "ssl2": 0, "ssl30": 1, "ssl3": 1, "tls10": 2, "tls11": 3, "tls12": 4, "tls13": 5}
FLAGS = {"expired": "expired-cert", "self_signed": "self-signed", "mismatched": "mismatched", "revoked": "revoked-cert",
         "untrusted": "untrusted", "wildcard_certificate": "wildcard-cert"}


def name(c):
    return NAMES.get(c, c)


def is_ip(h):
    try:
        ipaddress.ip_address(h)
        return True
    except ValueError:
        return False


def rule_match(r, h):
    if "/" in r or is_ip(r):
        try:
            return ipaddress.ip_address(h) in ipaddress.ip_network(r, strict=False)
        except ValueError:
            return False
    if r.startswith("*."):
        return h.endswith(r[1:])
    return h == r


def in_scope(h):
    if not rules:
        return True
    h = h.lower().rstrip(".")
    if any(rule_match(r[1:].strip(), h) for r in rules if r.startswith("!")):
        return False
    return any(rule_match(r, h) for r in rules if not r.startswith("!"))


def error_text(e):
    m = re.search(r'cause="([^"]*)"', e or "")
    if m:
        return m.group(1)
    e = (e or "").split(";", 1)[0].strip()
    return e or "no response"


def base(e):
    h = e["host"]
    if ":" in h:
        h = "[" + h + "]"
    s = h + (":" + str(e["port"]) if e.get("port") not in (None, "") else "")
    if e.get("sni") and e["sni"].lower() != e["host"].lower():
        s += " sni=" + e["sni"]
    return s


events = []
for line in open(raw):
    line = line.strip()
    if not line.startswith("{"):
        continue
    e = json.loads(line)
    e["host"] = e.get("host") or e.get("ip") or ""
    if e["host"]:
        events.append(e)
ips = {}
for e in events:
    ips.setdefault(base(e), set()).add(e.get("ip", ""))


def in_group(g, loc, ip):
    locs = set(g.get("locations", []))
    if g.get("ip") and g["ip"] != ip:
        return False
    return loc in locs or (loc + " [" + ip + "]") in locs


def finding_has(fid, loc):
    for f in o["findings"]:
        if f["id"] == fid and any(l == loc or l.startswith(loc + " [") for l in f["locations"]):
            return True
    return False


miss = []
seen = set()
out_of_scope = 0
for e in events:
    if not in_scope(e["host"]):
        out_of_scope += 1
        continue
    key = json.dumps({k: v for k, v in e.items() if k != "timestamp"}, sort_keys=True)
    if key in seen:
        continue  # an exact repeat, counted in omitted.duplicates
    seen.add(key)
    loc = base(e)
    if len(ips[loc]) > 1 and e.get("ip"):
        loc += " [" + e["ip"] + "]"
    ip = e.get("ip", "")
    failed = not e.get("probe_status") and not e.get("tls_version") and not e.get("subject_dn") and not e.get("subject_cn")
    if failed:
        if not any(g["id"].startswith("failed-") and g.get("error") == error_text(e.get("error")) and in_group(g, loc, ip) for g in o["groups"]):
            miss.append((loc, "failed", error_text(e.get("error"))))
        continue

    # TLS configuration
    versions = sorted({v.lower() for v in e.get("version_enum") or []}, key=lambda v: (ORDER.get(v, 9), v))
    pairs = {(ce["version"].lower(), name(c)) for ce in e.get("cipher_enum") or [] for cs in (ce.get("ciphers") or {}).values() for c in cs}
    ok = False
    for g in o["groups"]:
        if not g["id"].startswith("tls-") or not in_group(g, loc, ip):
            continue
        if g.get("version", "") != e.get("tls_version", "") or g.get("cipher", "") != name(e.get("cipher", "")):
            continue
        if g.get("versions", []) != versions:
            continue
        have = {(v, c) for k, cs in (g.get("ciphers") or {}).items() for v in k.split(",") for c in cs}
        if pairs - have:
            continue
        ok = True
    if not ok:
        miss.append((loc, "tls", e.get("tls_version"), e.get("cipher"), versions, len(pairs)))

    # certificate
    fp = e.get("fingerprint_hash") or {}
    if fp or e.get("subject_dn") or e.get("subject_cn"):
        subject = e.get("subject_dn") or ("CN=" + e["subject_cn"] if e.get("subject_cn") else "")
        issuer = e.get("issuer_dn") or ("CN=" + e["issuer_cn"] if e.get("issuer_cn") else "")
        san = e.get("subject_an") or ([e["subject_cn"]] if e.get("subject_cn") else [])
        ok = False
        for g in o["groups"]:
            c = g.get("cert")
            if not c or not in_group(g, loc, ip):
                continue
            fpo = c.get("sha256") or c.get("sha1") or c.get("md5") or ""
            want = fp.get("sha256") or fp.get("sha1") or fp.get("md5") or ""
            if fpo != want or c.get("subject", "") != subject or c.get("issuer", "") != issuer:
                continue
            if c.get("not_before", "") != e.get("not_before", "") or c.get("not_after", "") != e.get("not_after", ""):
                continue
            if (c.get("san") or ([e["subject_cn"]] if e.get("subject_cn") else [])) != san:
                continue
            ok = True
        if not ok:
            miss.append((loc, "cert", want, subject))

    # issues
    for flag, fid in FLAGS.items():
        if e.get(flag) and not finding_has(fid, loc):
            miss.append((loc, "flag", flag))
    vs = set(versions) | {e.get("tls_version", "")}
    if vs & {"ssl30", "ssl3", "ssl20", "ssl2"} and not finding_has("sslv3", loc):
        miss.append((loc, "version", "sslv3"))
    if vs & {"tls10", "tls11"} and not finding_has("old-tls", loc):
        miss.append((loc, "version", "tls10/tls11"))

if out_of_scope != (o.get("omitted") or {}).get("out_of_scope", 0):
    miss.append(("out_of_scope", out_of_scope, (o.get("omitted") or {}).get("out_of_scope", 0)))
oos = f", {out_of_scope} out of scope" if out_of_scope else ""
print(f"{len(events)} tlsx results ({len(seen)} distinct{oos}), {len(miss)} missing from output", "truncated" if o.get("budget") else "")
for m in miss[:5]:
    print("  MISSING", m)
sys.exit(1 if miss else 0)
