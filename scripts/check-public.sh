#!/usr/bin/env bash
# Fails if any file that would be committed contains hints at a concrete environment
# (private IPs, e-mail addresses, home paths) or a pattern from the local denylist.
#
# Local denylist (gitignored): local/public-denylist.txt — one extended regex per line,
# e.g. own domains, hostnames, public IPs. Lines starting with '#' are ignored.
#
# Usage: scripts/check-public.sh
set -euo pipefail
cd "$(dirname "$0")/.."

generic=(
  '\b10\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\b'
  '\b172\.(1[6-9]|2[0-9]|3[01])\.[0-9]{1,3}\.[0-9]{1,3}\b'
  '\b192\.168\.[0-9]{1,3}\.[0-9]{1,3}\b'
  '[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}'
  '/(Users|home)/[A-Za-z0-9._-]+'
  '^-----BEGIN [A-Z ]*PRIVATE KEY-----$'
)
patterns=("${generic[@]}")
if [[ -f local/public-denylist.txt ]]; then
  while IFS= read -r line; do
    [[ -z $line || $line == \#* ]] || patterns+=("$line")
  done < local/public-denylist.txt
fi

# Documentation examples (RFC 2606 / RFC 5737) are fine.
allow='(example\.(com|net|org)|192\.0\.2\.|198\.51\.100\.|203\.0\.113\.|noreply@anthropic\.com|noreply@example\.com)'

found=0
# Key stores and binaries are never committed (grep -I would skip them).
if bad=$(git ls-files --cached --others --exclude-standard \
    | grep -iE '\.(p12|pfx|jks|keystore|key|der|jar|zip|class)$'); then
  echo "$bad"
  found=1
fi
count=$(git ls-files -z --cached --others --exclude-standard | tr -cd '\0' | wc -c | tr -d ' ')
for p in "${patterns[@]}"; do
  # Check each match on its own, so an allowed example cannot hide a real value on the same line.
  if hits=$(git ls-files -z --cached --others --exclude-standard \
      | xargs -0 grep -nIoE -- "$p" 2>/dev/null | grep -vE -- ":[0-9]+:$allow"); then
    echo "$hits"
    found=1
  fi
done

if [[ $found -eq 1 ]]; then
  echo "check-public: FAILED — environment-specific content found (see above)" >&2
  exit 1
fi
echo "check-public: OK ($count files checked)"
