#!/usr/bin/env bash
# Verifies that the resolved TLM plugin SDK jar and POM are exactly the reviewed ones. The SDK comes from a
# mutable GitHub Pages Maven repository, so a silently replaced artifact must fail the build. The POM is pinned
# too, because it decides which further dependencies end up in the plugin.
# Run it after resolving and BEFORE any build or test, so no SDK code runs unverified:
#   mvn -s settings.xml org.apache.maven.plugins:maven-dependency-plugin:3.8.1:resolve && scripts/verify-sdk.sh
# Update the pinned values deliberately when upgrading the SDK.
set -euo pipefail

version=1.2
dir="${MAVEN_REPO:-$HOME/.m2/repository}/com/digicert/tlm/plugin-sdk/$version"

check() {
  local file=$dir/$1 expected=$2 actual
  [[ -f $file ]] || { echo "verify-sdk: $file not found - resolve the dependencies first" >&2; exit 1; }
  actual=$( (sha256sum "$file" 2>/dev/null || shasum -a 256 "$file") | cut -c1-64)
  if [[ $actual != "$expected" ]]; then
    echo "verify-sdk: FAILED - $1 has sha256 $actual, expected $expected" >&2
    exit 1
  fi
}

check "plugin-sdk-$version.jar" beb31c1f07cf8b4264b13221a2875e82d37feaa0851ff351637c2a13cf8d4ed5
check "plugin-sdk-$version.pom" dbbccfef4f28898144dc6d18de3bc4c0f75c13142028fce8626b1746d977a319
echo "verify-sdk: OK (plugin-sdk-$version.jar and .pom)"
