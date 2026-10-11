#!/usr/bin/env bash
# Runs one plugin action the way the TLM sensor does: writes plugin-info.json into an empty working
# directory, starts the fat JAR and captures the response the SDK uploads to TPM_COMMUNICATION_URL.
# plugin-info.json mirrors what a real TLM sensor delivers (lower-case stages, name "Custom", extra settings,
# and the API key Base64-encoded as TLM does for "sensitive" settings).
#
# Usage: KEMP_HOST=lb.example.com KEMP_PORT=443 KEMP_APIKEY=... \
#          scripts/run-plugin-action.sh <action> ['<parameters-json>']
#   action: testConnection | refreshConfiguration | generateCsr | installCertificate | validateCertificate
set -euo pipefail

action=${1:?usage: $0 <action> ['<parameters-json>']}
params=${2:-'{}'}
: "${KEMP_HOST:?}" "${KEMP_APIKEY:?}"
root="$(cd "$(dirname "$0")/.." && pwd)"
version=$(sed -n 's:.*<version>\([0-9][0-9.]*\)</version>.*:\1:p' "$root/pom.xml" | head -1)
jar="$root/target/kemp-loadmaster-tlm-plugin-$version.jar"
[[ -f $jar ]] || { echo "build first: mvn -s settings.xml package" >&2; exit 2; }

umask 077
receiver=
work=$(mktemp -d)
# plugin-info.json holds the API key: remove the work dir first, whatever happens.
trap 'rm -rf "$work"; if [[ -n $receiver ]]; then kill "$receiver" 2>/dev/null; wait "$receiver" 2>/dev/null || true; fi' EXIT

jq -n --arg h "$KEMP_HOST" --arg p "${KEMP_PORT:-443}" --arg a "$action" --arg v "$version" --argjson par "$params" '{
  executions: [
    {stage: "config", args: {name: "Custom", version: $v, baseRestApiUrl: null, plugin_upgrade: "true",
                             managementHost: $h, managementPort: $p, apiKey: ($ENV.KEMP_APIKEY | @base64)}},
    {stage: "run", args: {action: $a, parameters: $par}}
  ],
  environment: ["PLUGIN_LOG_LVL=" + ($ENV.PLUGIN_LOG_LVL // "DEBUG")]
}' > "$work/plugin-info.json"

port=$(python3 -I -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1])')
python3 -I - "$port" "$work/response.json" <<'PY' &
import http.server, sys
class Receiver(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("Content-Length", 0)))
        open(sys.argv[2], "ab").write(body + b"\n")
        self.send_response(200); self.end_headers(); self.wfile.write(b"{}")
    def log_message(self, *args): pass
http.server.HTTPServer(("127.0.0.1", int(sys.argv[1])), Receiver).serve_forever()
PY
receiver=$!
sleep 0.5

(cd "$work" && TPM_COMMUNICATION_URL="http://127.0.0.1:$port/upload?authorization=local&x-run-id=local" \
  java -Djava.io.tmpdir="${PLUGIN_TMPDIR:-${TMPDIR:-/tmp}}" -jar "$jar") > "$work/plugin.log" 2>&1 || true

echo "---- plugin log (tail)"; tail -n "${LOG_LINES:-15}" "$work/plugin.log"
echo "---- response"; jq . "$work/response.json" 2>/dev/null || cat "$work/response.json" 2>/dev/null || echo "(none)"
