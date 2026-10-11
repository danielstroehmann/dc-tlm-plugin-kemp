#!/usr/bin/env bash
# Generates a self-signed test certificate for the Kemp testbed.
# Output (gitignored): local/testbed/certs/<identifier>.pem  = cert + unencrypted key, the format
#                      Kemp's "Import Certificate" accepts in one file
#                      local/testbed/certs/<identifier>.crt  = cert only, for later comparison
#
# Usage: scripts/gen-testbed-cert.sh <identifier> <rsa|ec> <fqdn> [additional SAN ...]
#   e.g. scripts/gen-testbed-cert.sh tlmtest-c rsa '*.lab.example.com' lab.example.com
set -euo pipefail

[[ $# -ge 3 ]] || { echo "usage: $0 <identifier> <rsa|ec> <fqdn> [san ...]" >&2; exit 2; }
id=$1 kind=$2 cn=$3; shift 3

# Kemp certificate identifiers allow letters, digits, '-', '_' and '.'.
[[ $id =~ ^[A-Za-z0-9._-]+$ ]] || { echo "invalid identifier: $id" >&2; exit 2; }

case $kind in
  rsa) newkey=(-newkey rsa:2048) ;;
  ec)  newkey=(-newkey ec -pkeyopt ec_paramgen_curve:P-256) ;;
  *)   echo "key type must be rsa or ec" >&2; exit 2 ;;
esac

san="DNS:$cn"
for s in "$@"; do san+=",DNS:$s"; done

dir="$(cd "$(dirname "$0")/.." && pwd)/local/testbed/certs"
mkdir -p "$dir"
umask 077

openssl req -x509 -nodes "${newkey[@]}" -days 30 \
  -subj "/CN=$cn/O=TLM Kemp Testbed" -addext "subjectAltName=$san" \
  -keyout "$dir/$id.key" -out "$dir/$id.crt" 2>/dev/null

cat "$dir/$id.crt" "$dir/$id.key" > "$dir/$id.pem"
rm "$dir/$id.key"

echo "$dir/$id.pem  ($(openssl x509 -in "$dir/$id.crt" -noout -fingerprint -sha256 | cut -d= -f2))"
