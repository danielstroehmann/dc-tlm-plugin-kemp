# Preparing Kemp LoadMaster for the TLM Plugin

This guide describes how a Kemp/Progress LoadMaster must be configured so that the
DigiCert Trust Lifecycle Manager (TLM) plugin can manage its certificates. It is intended for
LoadMaster administrators. Menu names of the Kemp web UI are given exactly as they appear in the UI.

> Uploading the plugin and creating the connector in TLM: see [README.md](README.md).
> Verified on LoadMaster 7.2.63.2 (Free LoadMaster).

---

## Overview

| Step | Where in the LoadMaster | Required |
|---|---|---|
| 1. Check firmware | System Administration > Update Software | yes |
| 2. Enable the API | Certificates & Security > Remote Access | yes |
| 3. Configure session management | Certificates & Security > Admin WUI Access | yes |
| 4. Create a dedicated API user | System Administration > User Management | yes |
| 5. Generate an API key | System Administration > User Management | yes |
| 6. Management certificate (no preparation needed) | Certificates & Security > Admin WUI Access | – |
| 7. Allow network access from the sensor | Firewall / network | yes |
| 8. Test the connection | Machine in the sensor's network | recommended |

---

## 1. Firmware

- **LoadMaster firmware 7.2.50 or later** is required. The plugin uses the JSON API
  (`/accessv2`), which is only available from this version on.
- The installed version is shown at the top of the web UI, e.g. `Vers:7.2.63.2.bc23afa.RELEASE`.

## 2. Enable the API

The API is **disabled** by default.

1. Open **Certificates & Security > Remote Access**.
2. Enable **"Enable API Interface"** and save.

As long as the API is disabled, the LoadMaster responds on `/access` and `/accessv2` with
`404 Not found – Document is not accessible`.

> The API runs on the same port as the web UI (usually **443**; in Azure/AWS images and
> often on-premises too, **8443**). If a different API port is configured on the LoadMaster, it must
> be entered in the plugin later. On the wrong port the API also responds with 404.

## 3. Configure session management

The JSON API only works with these two settings:

1. Open **Certificates & Security > Admin WUI Access**.
2. **"Enable Session Management"** → **on**
3. **"Require Basic Authentication"** → **off**

## 4. Create a dedicated API user

The plugin should **not** use the default administrator `bal`, because it has unrestricted
permissions. Instead, create a dedicated user with minimal permissions:

1. Open **System Administration > User Management**.
2. Create a new local user, e.g. `api` or `tlm-plugin`, with a strong password.
3. Assign permissions according to the desired scope:

**Option "Standard": Virtual Services (cases A–E), minimal permissions**

| Permission (web UI) | What the plugin needs it for | API commands |
|---|---|---|
| **Certificate Creation** | Upload, replace (renewal) and delete certificates with private key | `addcert`, `delcert` |
| **Intermediate Certificates** | Upload missing intermediate certificates of the CA | `addintermediate` |
| **Virtual Services** | Assign a certificate to a Virtual Service (initial provisioning, SNI) | `modvs` |

Reading (inventory, `listvs`, `listcert`, `readcert` etc.) does not require a dedicated permission; a
user without any role has read access. Other permissions such as "Real Servers", "Rules", "User
Administration" or "Certificate Backup" are **not** needed.

**Option "With web UI certificate" (case H, optional)**

| Permission (web UI) | What the plugin needs it for | API commands |
|---|---|---|
| **All Permissions** | Additionally replace the certificate of the LoadMaster itself (web UI/API) | `set admincert` |

- Only "All Permissions" allows setting the admin certificate. Tested on 7.2.63.2: even all
  nine individual permissions combined are not sufficient.
- "All Permissions" means full administrative rights on the LoadMaster. Only grant it if the
  web UI certificate really is to be managed via TLM.

**The plugin detects the permissions on its own.** On "Test connection" and on every inventory it
checks what the API key is allowed to do. It does not change anything: it sends write commands with
deliberately invalid data and evaluates whether Kemp reports "no permission" or "invalid input".
- If "All Permissions" is missing, the plugin does not offer the web UI certificate.
- If one of the three standard permissions is missing, "Test connection" reports which one.

## 5. Generate an API key

The plugin authenticates with an API key, not with the password.

1. **System Administration > User Management**, click **Modify** for the API user.
2. Select **"Generate New APIKey"** and copy the displayed key.
3. Enter the key **only** in the plugin connector in TLM (where it is stored encrypted) or
   store it in a connected secrets manager (BeyondTrust, CyberArk, Delinea).

Notes:
- Up to **16 API keys** are possible per user; when a 17th is created, the oldest is deleted automatically.
- Treat the key like a password: do not share it by e-mail or chat, do not store it in scripts or
  repositories.
- Rotate the key regularly and after any possible exposure: generate a new key, enter it in TLM,
  delete the old key.

## 6. Management certificate

The plugin **accepts any certificate** presented by the web UI or API: self-signed or CA-issued,
with or without a matching hostname. Nothing needs to be prepared on the LoadMaster for this.

- The LoadMaster can be addressed via **IP address or hostname**.
- The plugin can also **manage the web UI certificate itself** (issue and renew it
  via TLM). A manually maintained CA certificate is not needed for this.
- If the web UI certificate is currently obtained via the built-in ACME client, the plugin does not
  offer it (see below). To hand it over to TLM, assign a regular certificate to the web UI first.

> **Security note:** Because the plugin does not verify the peer based on its certificate, the path
> between sensor and LoadMaster must be trusted — anyone able to impersonate the LoadMaster there
> obtains the API key and the private keys of the certificates being installed. An isolated management network or VLAN and an API
> user with the minimal permissions from step 4 are recommended.

## 7. Network access

- The **DigiCert sensor** running the plugin must reach the LoadMaster via **HTTPS on the
  management port** (443 or 8443).
- HA pairs are not supported yet. If used anyway, always use the **shared IP** or its hostname, not the
  address of an individual node.
- Optional: for Virtual Services that only use Kemp's **built-in certificate**, the sensor must also reach
  the Virtual Service's address and port. The plugin reads that certificate from the TLS handshake so TLM can
  offer "Renew", which installs the first real certificate. Without that access such services stay
  "unsecured" in TLM.
- The LoadMaster drops the connection if **more than 30 API calls arrive within 3 seconds**. Other
  automations accessing the same API at the same time count towards this limit.

## 8. Test the connection

From a machine in the sensor's network (replace the placeholders; do not leave the key in the shell
history):

```bash
curl -k -sS -H 'Content-Type: application/json' \
  -d '{"cmd":"get","param":"version","apikey":"<API-KEY>"}' \
  https://<loadmaster-hostname>:<port>/accessv2
```

Expected response:

```json
{ "code": 200, "version": "7.2.63.2.bc23afa.RELEASE", "status": "ok" }
```

| Response | Meaning |
|---|---|
| `404 Not found – Document is not accessible` | API not enabled (step 2) or wrong port |
| `401 Unauthorized – Permission Denied` | API key wrong or deleted (step 5) |
| TLS error from `curl` (`certificate verify failed`, hostname mismatch) | Not a problem for the plugin. Use `curl -k` for the manual test |
| Timeout | Check network / firewall between sensor and LoadMaster (step 7) |

---

## Important: certificates from the built-in ACME client

The LoadMaster can obtain and renew certificates itself via its **built-in ACME client**,
including from DigiCert (**Certificates & Security > ACME Certificates**).

- Such certificates are managed by the LoadMaster itself and can be neither replaced nor deleted via
  the regular certificate functions.
- The TLM plugin **does not manage ACME certificates**: Virtual Services using them (and an
  ACME-managed web UI certificate) are left out of the TLM inventory. A Virtual Service should be
  supplied either via ACME **or** via the TLM plugin, not both.
- If a Virtual Service previously supplied via ACME is to be managed via TLM in the future, first
  replace the ACME certificate there with a regular certificate.

Whether certificates are managed via ACME is shown in the list under **Certificates & Security > ACME
Certificates**.

---

## Checklist

- [ ] Firmware 7.2.50 or later
- [ ] "Enable API Interface" on
- [ ] "Enable Session Management" on, "Require Basic Authentication" off
- [ ] Dedicated API user with exactly the permissions Certificate Creation, Intermediate Certificates, Virtual Services
- [ ] API key generated and stored only in TLM or in the secrets manager
- [ ] Web UI certificate not ACME-managed, if the plugin is to manage it
- [ ] Management network between sensor and LoadMaster trusted (the plugin does not verify the certificate)
- [ ] Sensor reaches the LoadMaster via HTTPS on the management port
- [ ] Connection test returns `"status": "ok"`
- [ ] Virtual Services to be managed do not use ACME certificates
