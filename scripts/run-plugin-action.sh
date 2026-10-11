#!/usr/bin/env bash
# Runs one plugin action the way the TLM sensor does: writes plugin-info.json into an empty working
# directory, starts the fat JAR and captures the response the SDK uploads to TPM_COMMUNICATION_URL.
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
    {stage: "CONFIG", args: {name: "kemp-loadmaster-tlm-plugin", version: $v,
                             managementHost: $h, managementPort: $p, apiKey: $ENV.KEMP_APIKEY}},
    {stage: "RUN", args: {action: $a, parameters: $par}}
  ],
  environment: ["PLUGIN_LOG_LVL=INFO"]
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
