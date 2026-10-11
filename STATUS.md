# Status: TLM Plugin for Kemp LoadMaster

As of: 2026-10-11 · Phase: first plugin version 0.1.0

This document records which initial configurations on Kemp LoadMasters we assume, which TLS tasks
that are manual today the plugin is meant to automate, and which decisions are still open. How to
prepare the LoadMaster is described in [SETUP.md](SETUP.md).

---

## 1. Progress so far

| Topic | Status |
|---|---|
| SDK and examples | `plugin-sdk` 1.2 analyzed. The template is the `automation/` example (`AbstractAutomationWorkflow`) |
| Local toolchain | JDK 17, Maven 3.10, Docker, VS Code Java extensions installed; example plugin builds |
| Local testing without TLM | possible: input via `plugin-info.json`, response via HTTP to `TPM_COMMUNICATION_URL` |
| Test LoadMaster | Free LoadMaster 7.2.63.2 on the local network, API v1 + v2 enabled, API user with key |
| Write permissions of the API user | ✅ confirmed: `addcert`, `modvs` (SSL, `CertFile`, Reencrypt, SubVS) and `addrs` |
| Test environment | ✅ set up: cases A–E, F1/F2, H, details locally in `local/testbed/` (not in the repo) |
| Plugin 0.1.0 | ✅ built; all five actions verified live against the test LoadMaster (sensor simulated locally with `scripts/run-plugin-action.sh`): cases A–E, F1 and H end-to-end with a local test CA |
| Automated tests / review | ✅ 354 tests green (2 live smoke tests run on demand); two independent code reviews and a security review, findings fixed |
| TLM tenant with sensor | **still open** (needed for the end-to-end test with real issuance) |

---

## 2. What happens manually today

This is the typical manual process for a TLS certificate on a LoadMaster. The plugin is meant to
replace it:

1. Generate key and CSR: externally with OpenSSL or via **Certificates & Security > Generate
   CSR** in the web UI. The private key then usually ends up as a file somewhere.
2. Submit the CSR to the CA and retrieve the certificate.
3. Assemble certificate and key into a PEM or PFX file.
4. Upload it under **SSL Certificates > Import Certificate**, with a freely chosen name
   (identifier).
5. Upload missing intermediate certificates under **Intermediate Certificates**.
6. Assign the certificate to the Virtual Service.
7. On renewal, either "replace" the same identifier or create a new identifier,
   switch every affected Virtual Service over and delete the old certificate.
8. Track expiry dates in a spreadsheet or calendar.

Sources of error: forgotten renewals, wrong or missing intermediate certificates, private
keys in file shares, and Virtual Services that are overlooked during the switchover.

---

## 3. Assumed initial configurations

Rating: **in scope** = the plugin must be able to handle it · **limited** = is
supported, with limitations · **out of scope** = is detected but not managed.

### A. SSL offloading, one certificate per Virtual Service: in scope

The most common case.
- Virtual Service `IP:443/tcp` with **SSL Acceleration** on and exactly one certificate.
- The Real Servers behind it speak HTTP.
- Example: `192.0.2.10:443` with the certificate `www.example.com`.

### B. SSL re-encryption: in scope

- Like A, but the LoadMaster establishes TLS again towards the Real Server (**SSL Re-Encrypt**).
- The plugin manages only the certificate on the front side (client to LoadMaster).
- The certificates on the Real Servers are not included.

### C. One certificate for multiple Virtual Services: in scope

- A wildcard or SAN certificate used by multiple Virtual Services, e.g. `:443` and `:8443`
  or multiple IPs.
- If the certificate is replaced under its identifier, **all** Virtual Services pick it up
  automatically.
- The plugin must detect that a certificate is attached in multiple places. In TLM it appears as
  one certificate with multiple endpoints.

### D. Multiple certificates on one Virtual Service (SNI): in scope

- A Virtual Service with multiple certificates. The LoadMaster selects one based on the hostname sent
  by the client.
- When making changes, the plugin may **only replace its own certificate** in the list and must leave
  all other entries unchanged.

### E. Content switching with sub-Virtual Services: in scope

- The certificate is attached to the parent Virtual Service; the sub-Virtual Services share its
  TLS.
- The plugin always targets the parent Virtual Service.
- Example on the test LoadMaster: Virtual Service 2 with sub-Virtual Service 3.

### F. Virtual Service without its own certificate: limited, decision open

- A Virtual Service that uses SSL but only has the self-signed Kemp factory certificate.
- Or a plain HTTP Virtual Service for which TLS is yet to be set up.
- In TLM such endpoints appear as "unsecured", and a certificate can be requested there.
- **Open:** May the plugin enable SSL on the Virtual Service itself for this, or only serve Virtual
  Services where SSL is already on? (see section 6)

### G. Certificates from the built-in ACME client: out of scope

- The LoadMaster obtains and renews these certificates itself. Replacing them is technically blocked.
- The plugin leaves Virtual Services that use ACME certificates out of the inventory (so TLM does not
  schedule renewals that must fail) and refuses to install on them. The same applies to an
  ACME-managed web UI certificate (case H is then not offered).
- Example: both certificates on the test LoadMaster.

### H. Certificate of the LoadMaster itself (web UI/API): in scope

- The certificate of the Kemp web UI or API (`admincert`). Per the decision of 2026-10-11, the
  plugin manages it as well, as a separate endpoint alongside the Virtual Services.
- Process: upload a new certificate under its own identifier, then assign it to the web UI
  (`set admincert`), or replace the existing identifier.
- The plugin itself works over exactly this connection. After the replacement, the LoadMaster presents
  a different certificate. This is not a problem, because the plugin accepts any certificate (see
  section 6).
- **Verified on 2026-10-11:** Switching the admin certificate takes effect immediately, without web UI
  downtime and without dropping active sessions (details locally in `local/testbed/` (not in the repo)).
- **Verified on 2026-10-11: replacing (`replace=1`) the active admin certificate.**
  - The certificate is replaced, **but the assignment as admin certificate is lost.**
  - The web UI keeps serving the old certificate until the admin certificate is set
    again. After that it serves the new one immediately. No downtime.
  - **Consequence for the plugin:** In case H, uploading must always be followed by `set admincert`,
    regardless of whether the certificate was replaced or uploaded under a new identifier.
- **Open:**
  - ~~Which Kemp permission allows `set admincert`?~~ **Resolved on 2026-10-11: only "All Permissions".**
    All nine individual permissions combined still result in "Permission denied".
  - With "All Permissions", the complete process via API is confirmed: `addcert replace=1`, then
    `set admincert`. The web UI serves the new certificate within one second, without
    downtime.
  - **Decided:** Case H is optional and is offered automatically based on the permissions (section 6).
  - Does an ACME renewal of the former web UI certificate reset the
    admin certificate? Check `get admincert` afterwards.

### I. HA pair: out of scope (decision of 2026-10-11)

- Not supported and not tested in the first version.
- For information: later support would work via the shared IP and write only to the
  active node.
- We assume that the LoadMaster synchronizes certificates to the standby node. The
  Kemp documentation does not state this explicitly.
- The Free LoadMaster cannot do HA, so this cannot be tested without a second license.

### J. Client certificate verification and certificates on the Real Servers: out of scope

- Client certificate verification (mTLS), Reverse SSL, ESP/SSO and certificates on the Real Servers
  are not in scope.
- The existing configuration for these remains untouched.

### General assumptions

- **One connector per LoadMaster or HA pair.** The management address is unique.
- **Key types:** RSA 2048/3072/4096 and EC P-256/P-384. What is actually used is defined by the
  certificate profile in TLM.
- **Identifiers have grown historically.** Existing certificates carry arbitrary names, e.g.
  `www_example_2025` or `wildcard-neu`. The plugin must not rely on a naming scheme.
- **Intermediate certificates are maintained inconsistently**: uploaded manually, sometimes duplicated or
  outdated, with arbitrary names. The plugin identifies existing intermediate certificates by content
  (fingerprint), not by name. It adds missing ones and deletes none, because they are shared by all
  certificates.
- **Cipher sets, TLS versions, Real Servers and other Virtual Service settings** remain
  unchanged. The plugin only changes certificates and their assignment.
- **The sensor only reaches the management interface**, not necessarily the data IPs of the Virtual
  Services. Post-installation validation therefore runs via the API, not via a
  TLS connection to the Virtual Service.

---

## 4. What the plugin should automate

| Task | Manual today | With the plugin | TLM action |
|---|---|---|---|
| Inventory | Maintain a list/spreadsheet | Automatically report Virtual Services, certificates, expiry dates and assignments to TLM | `refreshConfiguration` |
| Check connection | – | Check API reachability, key and permissions | `testConnection` |
| Initial provisioning | Steps 1–6 | Key and CSR on the sensor, certificate from TLM, upload, intermediate certificates, assignment | `generateCsr` → `installCertificate` |
| Renewal / reissue / CA change | Step 7 | Replacement without interruption, all affected Virtual Services pick up the new certificate | `generateCsr` → `installCertificate` |
| Post-installation check | Browser/OpenSSL | Check whether the Virtual Service really uses the new certificate | `validateCertificate` |
| Automatic renewal | Calendar | TLM starts the renewal before expiry on its own | (TLM schedule) |

---

## 5. Mapping in TLM (implemented in 0.1.0)

How TLM displays a plugin's inventory data is not documented and must be verified with a real
tenant. Implemented:

| TLM field | Kemp equivalent |
|---|---|
| Endpoint (`dataIp`, `port`) | Virtual Service `VSAddress:VSPort` |
| `alias` | NickName of the Virtual Service if unique, otherwise `IP:Port` |
| `partition` | does not exist in Kemp → fixed value `default` |
| `sslState` | always `1`; only Virtual Services with SSL termination are reported |
| `portWithCert` | `Port:Identifier1,Identifier2` |
| `certificates[]` | one entry per assigned certificate (`sni=true` if multiple), `serverParam` = Kemp identifier |
| `peerInfo` | HA status, empty without HA |
| Endpoint `management` | Web UI: management IP + WUI port with the `admincert`, only with "All Permissions" |

For `installCertificate`/`validateCertificate`, the target is looked up first via `ipAddress` + `port`,
then via the alias in `virtualServerName` (`default/<alias>` or `<alias>`).

---

## 6. Decisions

### Made

| Date | Decision | Rationale / consequence |
|---|---|---|
| 2026-10-11 | **Scope of the first version: cases A, B, C, D, E and H.** HA (I) is excluded. F is open, G and J are out of scope. | A test configuration with self-signed certificates is set up for each case, runbook locally in `local/testbed/` (not in the repo). |
| 2026-10-11 | **Case H is optional and is detected automatically.** On "Test connection" and during inventory, the plugin checks without side effects which permissions the API key has. Only with "All Permissions" does it offer the web UI certificate. For A–E, the three minimal permissions are sufficient. | Kemp allows `set admincert` only with "All Permissions". Permission check see section 7; guide for admins in [SETUP.md](SETUP.md). |
| 2026-10-11 | **The certificate of the LoadMaster itself (web UI/API) is managed as well**, in addition to the Virtual Services where automation makes sense. | Case H is in scope. |
| 2026-10-11 | **For the connection to the LoadMaster, the plugin accepts any certificate**: trusted or not, with or without a matching hostname. There is neither chain nor hostname verification. | The connection works with the self-signed factory certificate, via the IP address, and also after the plugin itself has replaced the web UI certificate. **Deliberately accepted risk:** anyone on the network between sensor and LoadMaster who impersonates the LoadMaster can capture the API key **and every private key the plugin installs** (they travel inside the `addcert` request), and can feed a fake inventory to TLM. Countermeasures are an isolated management network and an API user with minimal permissions. |

### Provisionally implemented (default in 0.1.0, confirmation pending)

The proposals were implemented for the first version. Each default can be changed.

| # | Question | Default in 0.1.0 |
|---|---|---|
| 1 | Renewal strategy | Replace under the existing identifier (`addcert replace=1`) if `currentCertificateThumbprint` matches a certificate of the target. All Virtual Services with this certificate pick it up. |
| 2 | Naming scheme for new certificates | `tlm-<CN>` (`*` → `wildcard`), with a UTC timestamp on collision. Intermediate certificates: `tlm-ica-<16 hex of the SHA-256>`. |
| 3 | Case F: enable SSL? | No. Only Virtual Services with SSL termination enabled are managed. F1 (factory certificate) is replaced during initial provisioning, F2 (without SSL) does not appear in the inventory. |
| 4 | Clean up old certificates | No, the plugin does not delete anything on the LoadMaster. |
| 5 | Supported API | JSON API only (firmware 7.2.50+). |
| 6 | Authentication | API key only. |
| 7 | Which Virtual Services | All top-level Virtual Services with SSL termination, except those with ACME certificates. |

Further behavior rules:
- Initial provisioning on a Virtual Service with existing certificates (without a matching thumbprint):
  an existing certificate for the **same host names** is superseded at its list position (clients
  without SNI get the first entry, verified on 7.2.63); only certificates for other host names
  remain and the new one is appended (SNI).
- A thumbprint that matches nothing on the target aborts the install before anything is written.
- Installs are repeatable: if the certificate is already in place, the plugin reports success
  without changes. If assigning a newly uploaded certificate fails, the upload is rolled back.
- All permission checks happen before the first write.
- If a replaced certificate is also the web UI certificate, the assignment is set again
  (with "All Permissions"); without that permission the install is refused before any write.
- The certificate package behind `certificateLink` is downloaded by the plugin itself (TLS verified
  against the JVM trust store, no https→http redirects, size limits) instead of the SDK helper, which
  skips TLS verification. The issued certificate must not be a CA, must be currently valid and, if it
  carries an extended key usage, allow TLS server authentication.
- A flow's private key is kept at most 30 days on the sensor; flows that take longer (e.g. manual
  approval) fail at installation and must be restarted.

---

## 7. Detecting permissions and minimal permissions

### Detection without side effects (confirmed on 2026-10-11)

For write commands, Kemp checks **the permission first, then the input**. A write command with
deliberately invalid data therefore returns:
- `Permission denied`: the permission is missing.
- A validation error: the permission is present. Nothing was changed.

| Capability | Probe (invalid input) | Response if allowed |
|---|---|---|
| Write certificates | `addcert` with `cert=tlmprobe-does-not-exist`, data not a certificate | `Command Failed: Invalid Format Input` |
| Delete certificates | `delcert` with a non-existent name | `Command Failed: Invalid certificate file` |
| Intermediate certificates | `addintermediate` with invalid data | `Command Failed: Certificate Format Invalid` |
| Modify Virtual Services | `modvs` with `vs=2147483646` and no change parameters | `Unknown VS` |
| Admin certificate (case H) | `set admincert` with a non-existent name | `Command Failed: Unknown Certificate` |

- Probe script: `scripts/kemp-perm-probe.sh` (same logic as later in the plugin).
- Confirmed with "All Permissions": all probes reach validation, state unchanged afterwards.
- Confirmed with the three standard permissions: `set admincert` returns `Permission denied`.

### Still to be verified

The exact mapping permission → command (see [SETUP.md](SETUP.md)) follows the Kemp documentation and
has been tested as a whole: with the three permissions, `addcert`, `modvs` and `addrs` worked. It has
not yet been verified individually. For this, one run of `scripts/kemp-perm-probe.sh` each with:
1. no permission: is reading allowed? Do all write probes return `Permission denied`?
2. only "Certificate Creation"
3. only "Intermediate Certificates"
4. only "Virtual Services"

This also verifies that the permission check comes **before** the input check when a permission
is missing.

## 8. Next steps

- [ ] Confirm or change the defaults from section 6
- [x] Check write permissions of the API user
- [x] Set up test environment for A–E, F1/F2 and H (locally: `local/testbed/`)
- [ ] Clarify access to a TLM tenant with sensor
- [x] Plugin 0.1.0 implemented and verified live
- [x] Automated tests (354, test agent), two independent reviews, security review (full codebase)
- [ ] Verify permissions individually (section 7) and reset user `api` to minimal permissions
- [x] License: MIT
- [ ] Upload to a TLM tenant and end-to-end test with a real sensor
