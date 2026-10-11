#!/usr/bin/env bash
# Verifies that the resolved TLM plugin SDK jar is exactly the reviewed one. The SDK comes from a mutable
# GitHub Pages Maven repository, so a silently replaced artifact must fail the build.
# Update the pinned value deliberately when upgrading the SDK.
set -euo pipefail

version=1.2
expected=beb31c1f07cf8b4264b13221a2875e82d37feaa0851ff351637c2a13cf8d4ed5
jar="${MAVEN_REPO:-$HOME/.m2/repository}/com/digicert/tlm/plugin-sdk/$version/plugin-sdk-$version.jar"

[[ -f $jar ]] || { echo "verify-sdk: $jar not found — run the Maven build first" >&2; exit 1; }
actual=$( (sha256sum "$jar" 2>/dev/null || shasum -a 256 "$jar") | cut -c1-64)
if [[ $actual != "$expected" ]]; then
  echo "verify-sdk: FAILED — plugin-sdk-$version.jar has sha256 $actual, expected $expected" >&2
  exit 1
fi
echo "verify-sdk: OK (plugin-sdk-$version.jar)"
