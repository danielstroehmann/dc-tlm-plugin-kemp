#!/usr/bin/env bash
# Probes which LoadMaster API operations the given API key may perform — without changing anything.
# Write operations are sent with deliberately invalid input: Kemp checks the permission first, so the
# answer is either "Permission denied" (no right) or a validation error (right present, nothing done).
#
# Usage: KEMP_APIKEY=... scripts/kemp-perm-probe.sh <host[:port]>
set -euo pipefail

host=${1:?usage: KEMP_APIKEY=... $0 <host[:port]>}
: "${KEMP_APIKEY:?KEMP_APIKEY not set}"
url="https://$host/accessv2"
probe_name="tlmprobe-does-not-exist"

call() {
  # Self-signed or mismatching management certs are accepted on purpose (project decision).
  jq -nc "$1 + {apikey: \$ENV.KEMP_APIKEY}" \
    | curl -sk -m 15 -H 'Content-Type: application/json' --data-binary @- "$url"
  sleep 0.4 # stay below Kemp's limit of 30 calls per 3 s
}

report() { # <label> <json-request>
  local resp status msg verdict
  resp=$(call "$2")
  status=$(jq -r '.status // "?"' <<<"$resp" 2>/dev/null || echo "?")
  msg=$(jq -r '.message // ""' <<<"$resp" 2>/dev/null || echo "non-JSON response")
  if [[ $msg == "Permission denied" ]]; then verdict="DENIED"
  elif [[ $status == "ok" ]]; then verdict="ALLOWED"
  elif [[ $status == "fail" ]]; then verdict="ALLOWED (validation: $msg)"
  else verdict="UNKNOWN ($msg)"; fi
  printf "%-28s %s\n" "$1" "$verdict"
}

invalid_data=$(printf 'not-a-certificate' | base64)

echo "== read"
report "get version"              '{cmd:"get",param:"version"}'
report "get admincert"            '{cmd:"get",param:"admincert"}'
report "listvs"                   '{cmd:"listvs"}'
report "listcert"                 '{cmd:"listcert"}'
first_cert=$(call '{cmd:"listcert"}' | jq -r '.cert[0].name // empty')
# The name comes from the LoadMaster — pass it as data, never as part of the jq program.
report "readcert"                 "$(jq -nc --arg c "${first_cert:-$probe_name}" '{cmd:"readcert",cert:$c}')"
report "listintermediate"         '{cmd:"listintermediate"}'
report "listacmecert"             '{cmd:"listacmecert",acmetype:"2"}'
report "licenseinfo"              '{cmd:"licenseinfo"}'
report "showiface"                '{cmd:"showiface"}'

echo "== write (invalid input, no side effects)"
report "addcert"                  "{cmd:\"addcert\",cert:\"$probe_name\",replace:\"0\",data:\"$invalid_data\"}"
report "delcert"                  "{cmd:\"delcert\",cert:\"$probe_name\"}"
report "addintermediate"          "{cmd:\"addintermediate\",cert:\"$probe_name\",data:\"$invalid_data\"}"
report "delintermediate"          "{cmd:\"delintermediate\",cert:\"$probe_name\"}"
# No change parameters: even if the index existed, nothing would be modified.
report "modvs"                    '{cmd:"modvs",vs:"2147483646"}'
report "set admincert"            "{cmd:\"set\",param:\"admincert\",value:\"$probe_name\"}"
