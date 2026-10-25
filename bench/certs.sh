#!/usr/bin/env bash
# Generates the certificates of the local lab with openssl: a lab CA and one leaf per kind.
#
# usage: bench/certs.sh <dir>
#
#   good      signed by the lab CA, localhost + 127.0.0.1, valid for a year
#   app       the same, a second certificate (so the noisy run has two)
#   expired   signed by the lab CA, expired on 2025-01-01
#   self      self-signed, localhost + 127.0.0.1
#   mismatch  signed by the lab CA, for other.example only
#   soon      signed by the lab CA, expires in 10 days
#   wildcard  signed by the lab CA, *.lab.test + localhost + 127.0.0.1
#
# The lab CA is not in any trust store, so every certificate is untrusted to tlsx; that is expected.
set -euo pipefail

D=${1:?usage: certs.sh <dir>}
mkdir -p "$D/ca"
cd "$D"
: > ca/index.txt
echo 1000 > ca/serial
cat > ca.cnf <<'EOF'
[ca]
default_ca = lab
[lab]
dir = ca
database = ca/index.txt
serial = ca/serial
new_certs_dir = ca
certificate = ca.pem
private_key = ca.key
default_md = sha256
policy = any
copy_extensions = copy
unique_subject = no
[any]
commonName = supplied
organizationName = optional
EOF

openssl req -x509 -newkey rsa:2048 -nodes -keyout ca.key -out ca.pem -days 3650 \
  -subj "/O=Raijin Lab/CN=Raijin Lab CA" 2>/dev/null

# leaf <name> <cn> <san> <startdate> <enddate>; dates are YYYYMMDDHHMMSSZ
leaf() {
  openssl req -newkey rsa:2048 -nodes -keyout "$1.key" -out "$1.csr" -subj "/O=Raijin Lab/CN=$2" \
    -addext "subjectAltName=$3" 2>/dev/null
  openssl ca -batch -config ca.cnf -in "$1.csr" -out "$1.pem" -notext -startdate "$4" -enddate "$5" 2>/dev/null
  rm "$1.csr"
}

now=$(date -u +%Y%m%d%H%M%SZ)
year=$(date -u -d '+365 days' +%Y%m%d%H%M%SZ)
leaf good localhost "DNS:localhost,IP:127.0.0.1" "$now" "$year"
leaf app localhost "DNS:localhost,DNS:app.localhost,IP:127.0.0.1" "$now" "$year"
leaf expired localhost "DNS:localhost,IP:127.0.0.1" 20240101000000Z 20250101000000Z
leaf mismatch other.example "DNS:other.example" "$now" "$year"
leaf soon localhost "DNS:localhost,IP:127.0.0.1" "$(date -u -d '-355 days' +%Y%m%d%H%M%SZ)" "$(date -u -d '+10 days' +%Y%m%d%H%M%SZ)"
leaf wildcard '*.lab.test' "DNS:*.lab.test,DNS:localhost,IP:127.0.0.1" "$now" "$year"
openssl req -x509 -newkey rsa:2048 -nodes -keyout self.key -out self.pem -days 365 \
  -subj "/O=Raijin Lab/CN=localhost" -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" 2>/dev/null
echo "certificates in $D"
