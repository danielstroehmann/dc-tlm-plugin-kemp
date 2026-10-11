# Changelog

All notable changes to this project. The section of a version is published as the release notes of
its GitHub Release. Versioning follows [SemVer](https://semver.org/).

## [Unreleased]

## [0.1.0]

First **alpha** of the Kemp LoadMaster automation plugin for DigiCert Trust Lifecycle Manager — for
evaluation, not for production.

- Inventory of TLS virtual services and their certificates (SNI and shared certificates included);
  virtual services using LoadMaster ACME certificates are left out.
- Key and CSR generation on the sensor (RSA 2048–8192, EC P-256/P-384); the private key is
  stored encrypted until installation and deleted afterwards.
- Installation and renewal: renewal in place keeps every virtual service binding; first installs
  supersede a certificate for the same host names; missing intermediates are added.
- Optional management of the LoadMaster web UI certificate, offered automatically when the API key
  has "All Permissions".
- Permission detection without side effects; "Test connection" reports missing Kemp permissions.
- Requires LoadMaster firmware 7.2.50+ (JSON API) and Java 17 on the sensor.

Known limitations of this alpha:

- Not yet tested end-to-end in a real TLM tenant with a sensor. All actions were verified against a
  LoadMaster 7.2.63 with a simulated sensor; how TLM presents the inventory and which request fields it
  sends are assumptions until then.
- HA pairs are not supported; virtual services using LoadMaster ACME certificates are skipped.
- The plugin accepts any TLS certificate of the LoadMaster (by design) — use a trusted management network;
  an impersonator on that path could obtain the API key and the private keys being installed.
- If renewing a certificate that is also the web UI certificate is interrupted between the upload and
  re-assigning the web UI, a retry reports success and the web UI keeps serving the previous
  certificate until it is re-assigned on the LoadMaster.
- Private keys are kept on the sensor for at most 30 days between CSR and installation. On Windows
  sensors the key file is protected by encryption only (no owner-only ACL).
