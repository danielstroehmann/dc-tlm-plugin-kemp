# Kemp LoadMaster Plugin for DigiCert Trust Lifecycle Manager

An automation plugin for DigiCert Trust Lifecycle Manager (TLM) that discovers, installs and renews the TLS
certificates of Kemp/Progress LoadMaster virtual services and of the LoadMaster web UI.

## Prepare the LoadMaster

1. **Firmware** 7.2.50 or later (the plugin uses the JSON API `/accessv2`).
2. **Enable the API:** *Certificates & Security > Remote Access* > **Enable API Interface**.
3. **Session management:** *Certificates & Security > Admin WUI Access* > **Enable Session Management** on,
   **Require Basic Authentication** off.
4. **Dedicated API user:** *System Administration > User Management*, a new local user (not `bal`) with exactly
   these permissions:
   - **Certificate Creation**
   - **Intermediate Certificates**
   - **Virtual Services**

   Optional: grant **All Permissions** instead, and the plugin also manages the certificate of the LoadMaster
   web UI. The plugin detects the permissions on its own.
5. **API key:** *Modify* the user > **Generate New APIKey**. Enter the key only in the TLM connector (or a
   connected secrets manager).
6. **Network:** the DigiCert sensor must reach the LoadMaster via HTTPS on the web UI port (443 or 8443). For
   virtual services that still use Kemp's built-in certificate, the sensor must also reach the virtual
   service's address and port.

Good to know:
- The plugin accepts any certificate presented by the LoadMaster, so the network between sensor and LoadMaster
  must be trusted.
- Virtual services with certificates from the LoadMaster's own ACME client are left out.
- Only virtual services with **SSL Acceleration** enabled are managed; the plugin never enables it.
- HA pairs are not supported yet.

Details, a connection test and a checklist: [SETUP.md](SETUP.md).

## Upload the plugin to TLM

Requires the TLM **Automation** feature, the **Plugin developer** role and a DigiCert sensor with Java 17.

1. Download the plugin ZIP and `configuration.json` (checksums in `SHA256SUMS`) from the
   [Releases](../../releases) page.
2. *Integrations > Plugins* > **Add plugin**: type **Automation**, the version from the ZIP name, upload both
   files, **Verify and create**. The check takes up to 10 minutes, until the status is *Active*.
3. *Integrations > Connectors* > **Add connector**: select the plugin (category *Appliances*), enter the
   sensor, LoadMaster address, port and API key, then **Test connection**; it reports missing Kemp permissions.

DigiCert documentation: [Add a plugin in Trust Lifecycle Manager](https://docs.digicert.com/en/trust-lifecycle-manager/build-your-inventory-and-ecosystem/plugins/add-a-plugin.html).

---

[MIT License](LICENSE), provided "as is", without warranty or liability. An independent project, not an
official DigiCert or Progress Kemp product and not supported by either company. Build and development: [DEVELOPMENT.md](DEVELOPMENT.md),
status and design decisions: [STATUS.md](STATUS.md), changes: [CHANGELOG.md](CHANGELOG.md).
