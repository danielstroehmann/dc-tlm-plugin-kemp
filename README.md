# Kemp LoadMaster Plugin for DigiCert Trust Lifecycle Manager

Automation plugin for **DigiCert Trust Lifecycle Manager (TLM)** that manages TLS certificates on
**Kemp/Progress LoadMaster**: inventory, key and CSR generation on the DigiCert sensor,
installation, renewal and validation. Built on the
[TLM Plugins SDK](https://github.com/digicert/tlm-plugins-sdk-dist) (`plugin-sdk` 1.2).

> Status: **0.2.0, pre-release.** All actions verified against LoadMaster 7.2.63, including the plugin input
> format of a real TLM sensor; not yet run end-to-end in a TLM tenant. See [STATUS.md](STATUS.md).

## What the plugin does

| Use case | Supported |
|---|---|
| SSL offloading, one certificate per Virtual Service | ✅ |
| SSL re-encryption (certificate on the client side) | ✅ |
| One certificate for multiple Virtual Services (wildcard/SAN) | ✅ renewal applies to all |
| Multiple certificates on one Virtual Service (SNI) | ✅ other entries are preserved |
| Content switching with sub-Virtual Services (SubVS) | ✅ certificate on the parent Virtual Service |
| Certificate of the LoadMaster web UI/API | ✅ optional, only with the Kemp permission "All Permissions" |
| Virtual Services with certificates from the built-in ACME client | ❌ detected and skipped |
| HA pairs | ❌ not yet |

The plugin detects on its own which permissions the API key has, and offers the web UI certificate
only if it is allowed to set it.

## Prerequisites

- LoadMaster firmware **7.2.50 or later** with the API enabled. Preparation, including minimal
  permissions, is described in **[SETUP.md](SETUP.md)**.
- TLM account with the Automation feature and the "Plugin developer" role, and a DigiCert sensor with
  **Java 17** that can reach the LoadMaster via HTTPS.
- To build: JDK 17 and Maven 3.6+.

## Download

Ready-to-upload packages are published on the repository's **Releases** page: the plugin ZIP,
`configuration.json` and `SHA256SUMS`, with release notes from [CHANGELOG.md](CHANGELOG.md).
How releases are made: [RELEASING.md](RELEASING.md).

## Build

```bash
mvn -s settings.xml clean package
```

Output:
- `plugin-dist/kemp-loadmaster-tlm-plugin-<version>.zip` — upload package for TLM
  (fat JAR + `plugin-meta.json`)
- `configuration.json` — configuration schema, uploaded together with the plugin when adding it

## Set up in TLM

1. **Integrations > Plugins > Add plugin**: type **Automation**, upload the ZIP and `configuration.json`,
   "Verify and create". Verification by TLM takes up to 10 minutes.
2. **Create a connector** (under Appliances) with sensor, LoadMaster address, port and API key.
3. "Test connection" reports missing Kemp permissions. After that, the inventory reads the Virtual
   Services and certificates.

## How it works

| TLM action | What the plugin does on the LoadMaster |
|---|---|
| `testConnection` | Read the version, check permissions without side effects |
| `refreshConfiguration` | Report Virtual Services with SSL termination, their certificates and, if applicable, the web UI |
| `generateCsr` | Generate key and CSR **on the sensor**; the key is cached encrypted until installation |
| `installCertificate` | Add missing intermediate certificates; renewal: replace the certificate under its name (all Virtual Services pick it up); initial provisioning: create as `tlm-<CN>` and assign |
| `validateCertificate` | Report back the certificate that is actually assigned |

Security-relevant properties:
- The private key is generated on the sensor and sent only to the LoadMaster. Between CSR and
  installation it is stored encrypted (password: the API key, which is not stored on disk) in a
  directory readable only by the sensor user (POSIX), and deleted afterwards (at the latest after 30 days).
- The plugin **accepts any TLS certificate presented by the LoadMaster** (a deliberate decision, so that
  it works with the factory certificate, via IP, and after it has replaced the web UI certificate itself).
  The path between sensor and LoadMaster must therefore be trusted: whoever can impersonate the
  LoadMaster there obtains the API key and the private keys being installed. See [SETUP.md](SETUP.md).

## Development

```bash
mvn -s settings.xml test                     # unit and integration tests (mock LoadMaster)
scripts/check-public.sh                      # before every commit: no environment-specific content
scripts/kemp-perm-probe.sh <host:port>       # check the permissions of an API key (set KEMP_APIKEY)
scripts/run-plugin-action.sh <action> [json] # run an action the way the sensor does (KEMP_HOST/PORT/APIKEY)
```

Material for tests against a real LoadMaster belongs in `local/` (excluded via `.gitignore`).

## License

[MIT](LICENSE) — free to use, modify and redistribute; provided "as is", without warranty or liability.

This is an independent project. It is not an official DigiCert or Progress Kemp product and is not
supported by either company.
