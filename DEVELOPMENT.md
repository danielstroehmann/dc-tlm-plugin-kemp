# Development

Built on the [TLM Plugins SDK](https://github.com/digicert/tlm-plugins-sdk-dist) (`plugin-sdk` 1.2). Requires
JDK 17 and Maven 3.6+.

## Build and test

```bash
mvn -s settings.xml org.apache.maven.plugins:maven-dependency-plugin:3.8.1:resolve
scripts/verify-sdk.sh                        # SDK jar and POM match the pinned checksums (before any build)
mvn -s settings.xml clean package            # tests, then the upload package
scripts/check-public.sh                      # before every commit: no environment-specific content
scripts/kemp-perm-probe.sh <host:port>       # permissions of an API key (set KEMP_APIKEY)
scripts/run-plugin-action.sh <action> [json] # run an action the way the sensor does (KEMP_HOST/PORT/APIKEY)
```

Output: `plugin-dist/kemp-loadmaster-tlm-plugin-<version>.zip` (fat JAR + `plugin-meta.json`). The
configuration schema `configuration.json` is uploaded together with it. Material for tests against a real
LoadMaster belongs in `local/` (excluded via `.gitignore`). Releases: [RELEASING.md](RELEASING.md).

## How it works

| TLM action | What the plugin does on the LoadMaster |
|---|---|
| `testConnection` | Read the version, check permissions without side effects |
| `refreshConfiguration` | Report virtual services with SSL enabled, their certificates and, with "All Permissions", the web UI |
| `generateCsr` | Generate key and CSR **on the sensor**; the key is kept encrypted until installation |
| `installCertificate` | Add missing intermediate certificates; renewal replaces the certificate under its name (all virtual services using it pick it up); a first certificate is created as `tlm-<CN>` and assigned |
| `validateCertificate` | Report back the certificate that is actually assigned |

| Use case | Supported |
|---|---|
| SSL offloading, one certificate per virtual service | yes |
| SSL re-encryption | yes (client-side certificate) |
| One certificate on several virtual services | yes, renewal applies to all |
| Several certificates on one virtual service (SNI) | yes; renewal keeps other entries, a first install replaces entries it fully covers (can change the default for clients without SNI) |
| Content switching (SubVS) | yes, certificate on the parent virtual service |
| First certificate for a service with Kemp's built-in certificate | yes, via "Renew" in TLM |
| LoadMaster web UI certificate | optional, only with "All Permissions" |
| Certificates from the LoadMaster's ACME client | no, skipped |
| HA pairs | no |

Security properties:
- The private key is generated on the sensor and sent only to the LoadMaster. Between CSR and installation it
  is stored encrypted (password: the API key, which is not stored on disk) in a directory readable only by the
  sensor user (POSIX; on Windows the directory's default permissions apply), and deleted afterwards (at the latest after 30 days).
- The certificate package is downloaded with TLS verified against the JVM trust store, without https-to-http
  redirects and with size limits.
- The plugin accepts any TLS certificate presented by the LoadMaster (deliberate decision, see
  [STATUS.md](STATUS.md)). Whoever can impersonate the LoadMaster on the network obtains the API key and the
  private keys being installed.
