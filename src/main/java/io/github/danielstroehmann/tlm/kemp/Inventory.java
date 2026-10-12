package io.github.danielstroehmann.tlm.kemp;

import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.function.BiFunction;

import com.digicert.tlm.workflows.automation.dto.RefreshConfigurationResponse;
import com.digicert.tlm.workflows.automation.dto.RefreshConfigurationResponse.AutomationInfo;
import com.digicert.tlm.workflows.automation.dto.RefreshConfigurationResponse.Certificate;
import com.digicert.tlm.workflows.automation.dto.RefreshConfigurationResponse.DataIpInfo;
import com.fasterxml.jackson.databind.JsonNode;

import io.github.danielstroehmann.tlm.kemp.client.KempApiException;
import io.github.danielstroehmann.tlm.kemp.client.KempClient;
import io.github.danielstroehmann.tlm.kemp.loadmaster.ServedCertificate;
import io.github.danielstroehmann.tlm.kemp.loadmaster.Snapshot;
import io.github.danielstroehmann.tlm.kemp.loadmaster.VirtualService;
import io.github.danielstroehmann.tlm.kemp.pki.Pem;
import lombok.extern.slf4j.Slf4j;

/** Builds the {@code refreshConfiguration} answer: appliance info, manageable endpoints and their certificates. */
@Slf4j
final class Inventory {

    /**
     * Identifier prefix reported for Kemp's built-in default certificate, which has no usable Kemp identifier.
     * Kemp generates one per virtual service, so the service index makes it unique.
     */
    static final String FACTORY_CERTIFICATE = "kemp-factory-certificate";

    /** Upper bound for all handshakes of one inventory, so unreachable data IPs cannot stall the refresh. */
    static final Duration HANDSHAKE_BUDGET = Duration.ofSeconds(30);

    private final KempClient client;
    private final Map<String, String> pemCache = new HashMap<>();

    /** Reads the certificate a service presents in the TLS handshake; replaceable in tests. */
    BiFunction<String, Integer, Optional<X509Certificate>> servedCertificate =
            (host, port) -> ServedCertificate.fetch(host, port, ServedCertificate.DEFAULT_TIMEOUT);

    Inventory(KempClient client) {
        this.client = client;
    }

    RefreshConfigurationResponse<JsonNode> build(Snapshot snapshot, boolean adminCertPermitted) throws KempApiException {
        List<DataIpInfo> endpoints = new ArrayList<>();
        List<Certificate> certificates = new ArrayList<>();
        Set<String> dataIps = new LinkedHashSet<>();
        long handshakeDeadline = System.nanoTime() + HANDSHAKE_BUDGET.toNanos();

        for (VirtualService vs : snapshot.manageable()) {
            if (vs.certificates().stream().anyMatch(snapshot.acmeCertificates()::contains)) {
                // Renewed by the LoadMaster's own ACME client — reporting it would let TLM schedule renewals that must fail.
                log.info("Skipping {}: uses ACME-managed certificates", vs.endpoint());
                continue;
            }
            dataIps.add(vs.address());
            String alias = snapshot.alias(vs);
            List<String> ids = vs.certificates();
            for (String id : ids) {
                certificate(vs.address(), vs.port(), id, ids.size() > 1).ifPresent(certificates::add);
            }
            if (vs.factoryCertificate() && System.nanoTime() - handshakeDeadline >= 0) {
                log.info("Skipping lookup of the built-in certificate on {}: time budget for handshakes used up",
                        vs.endpoint());
            } else if (vs.factoryCertificate()) {
                // Reported so TLM offers "Renew", which then performs the first install (TLM offers no request for
                // plugin endpoints without a certificate). Unreachable from the sensor: stays an unsecured endpoint.
                Optional<Certificate> factory = servedCertificate.apply(vs.address(), vs.port())
                        .flatMap(cert -> factoryCertificate(vs, cert));
                factory.ifPresent(certificates::add);
                ids = factory.isPresent() ? List.of(factory.get().getServerParam()) : ids;
            }
            endpoints.add(endpoint(snapshot, vs.address(), vs.port(), alias, ids));
        }

        // Case H is offered only when the API key may actually set the web UI certificate ("All Permissions") and
        // the certificate is not renewed by the LoadMaster's own ACME client.
        boolean manageWebUi = adminCertPermitted && snapshot.adminCertificateManageable();
        if (manageWebUi) {
            List<String> ids = snapshot.adminCertificate() == null ? List.of() : List.of(snapshot.adminCertificate());
            endpoints.add(endpoint(snapshot, snapshot.managementIp(), snapshot.wuiPort(), Snapshot.MANAGEMENT_ALIAS, ids));
            for (String id : ids) {
                certificate(snapshot.managementIp(), snapshot.wuiPort(), id, false).ifPresent(certificates::add);
            }
        }

        RefreshConfigurationResponse<JsonNode> response = new RefreshConfigurationResponse<>();
        response.setAutomationInfo(automationInfo(snapshot, dataIps));
        response.setDataIpInfo(endpoints);
        response.setCertificates(certificates);
        log.info("Inventory: {} endpoints, {} certificates, web UI certificate managed: {}",
                endpoints.size(), certificates.size(), manageWebUi);
        return response;
    }

    private AutomationInfo automationInfo(Snapshot snapshot, Set<String> dataIps) throws KempApiException {
        JsonNode license = client.licenseInfo();
        String model = license.path("ApplianceModel").asText("");
        AutomationInfo info = new AutomationInfo();
        info.setManagementIp(snapshot.managementIp());
        info.setHostName(client.get("hostname"));
        info.setOsName("Kemp LoadMaster");
        info.setOsFlavor(model);
        info.setOsVersion(client.get("version"));
        info.setOsArch(license.path("VlmPlatform").asText(""));
        info.setFips(model.toUpperCase(Locale.ROOT).contains("FIPS") ? "enabled" : "disabled");
        info.setDataIps(dataIps.toArray(String[]::new));
        String ha = client.haStatus();
        info.setPeerInfo(ha == null ? "" : snapshot.managementIp() + ":" + ha.toUpperCase());
        info.setPartitions(new String[] { Snapshot.PARTITION });
        return info;
    }

    private static DataIpInfo endpoint(Snapshot snapshot, String ip, int port, String alias, List<String> certIds) {
        DataIpInfo d = new DataIpInfo();
        d.setManagementIp(snapshot.managementIp());
        d.setDataIp(ip);
        d.setPort(port);
        d.setSslState(1);
        d.setPartition(Snapshot.PARTITION);
        d.setAlias(alias);
        d.setPortWithCert(port + ":" + String.join(",", certIds));
        return d;
    }

    private static Optional<Certificate> factoryCertificate(VirtualService vs, X509Certificate cert) {
        String ip = vs.address();
        int port = vs.port();
        try {
            Certificate c = new Certificate();
            c.setIpAddress(ip);
            c.setPort(port);
            c.setIpAndPort(ip + ":" + port);
            c.setCertificate(Pem.toPem(cert));
            c.setSni(false);
            c.setServerParam(FACTORY_CERTIFICATE + "-" + vs.index());
            c.setDomainName(Pem.commonName(cert));
            return Optional.of(c);
        } catch (Exception e) {
            log.warn("Factory certificate of {}:{} could not be encoded: {}", ip, port, e.getMessage());
            return Optional.empty();
        }
    }

    /** Empty if the certificate cannot be read — reporting an empty PEM would corrupt the TLM inventory. */
    private Optional<Certificate> certificate(String ip, int port, String id, boolean sni) throws KempApiException {
        String pem = pemCache.containsKey(id) ? pemCache.get(id) : read(id);
        pemCache.put(id, pem);
        if (pem == null) {
            return Optional.empty();
        }
        X509Certificate cert;
        try {
            cert = Pem.parseCertificate(pem);
        } catch (Exception e) {
            log.warn("Certificate '{}' could not be parsed: {}", id, e.getMessage());
            return Optional.empty();
        }
        Certificate c = new Certificate();
        c.setIpAddress(ip);
        c.setPort(port);
        c.setIpAndPort(ip + ":" + port);
        try {
            // Re-encoded from the parsed certificate, so no other LoadMaster-supplied text reaches TLM.
            c.setCertificate(Pem.toPem(cert));
        } catch (Exception e) {
            return Optional.empty();
        }
        c.setSni(sni);
        // serverParam carries the Kemp identifier, so TLM-side records can be traced back to the LoadMaster.
        c.setServerParam(id);
        c.setDomainName(Pem.commonName(cert));
        return Optional.of(c);
    }

    private String read(String id) throws KempApiException {
        try {
            return client.readCertificate(id);
        } catch (KempClient.KempTransportException e) {
            throw e;
        } catch (KempApiException e) {
            log.warn("readcert '{}' failed: {}", id, e.getMessage());
            return null;
        }
    }
}
