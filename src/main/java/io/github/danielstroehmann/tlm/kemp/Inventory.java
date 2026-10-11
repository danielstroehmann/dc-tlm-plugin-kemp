package io.github.danielstroehmann.tlm.kemp;

import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

import com.digicert.tlm.workflows.automation.dto.RefreshConfigurationResponse;
import com.digicert.tlm.workflows.automation.dto.RefreshConfigurationResponse.AutomationInfo;
import com.digicert.tlm.workflows.automation.dto.RefreshConfigurationResponse.Certificate;
import com.digicert.tlm.workflows.automation.dto.RefreshConfigurationResponse.DataIpInfo;
import com.fasterxml.jackson.databind.JsonNode;

import io.github.danielstroehmann.tlm.kemp.client.KempApiException;
import io.github.danielstroehmann.tlm.kemp.client.KempClient;
import io.github.danielstroehmann.tlm.kemp.loadmaster.Snapshot;
import io.github.danielstroehmann.tlm.kemp.loadmaster.VirtualService;
import io.github.danielstroehmann.tlm.kemp.pki.Pem;
import lombok.extern.slf4j.Slf4j;

/** Builds the {@code refreshConfiguration} answer: appliance info, manageable endpoints and their certificates. */
@Slf4j
final class Inventory {

    private final KempClient client;
    private final Map<String, String> pemCache = new HashMap<>();

    Inventory(KempClient client) {
        this.client = client;
    }

    RefreshConfigurationResponse<JsonNode> build(Snapshot snapshot, boolean adminCertPermitted) throws KempApiException {
        List<DataIpInfo> endpoints = new ArrayList<>();
        List<Certificate> certificates = new ArrayList<>();
        Set<String> dataIps = new LinkedHashSet<>();

        for (VirtualService vs : snapshot.manageable()) {
            if (vs.certificates().stream().anyMatch(snapshot.acmeCertificates()::contains)) {
                // Renewed by the LoadMaster's own ACME client — reporting it would let TLM schedule renewals that must fail.
                log.info("Skipping {}: uses ACME-managed certificates", vs.endpoint());
                continue;
            }
            dataIps.add(vs.address());
            String alias = snapshot.alias(vs);
            endpoints.add(endpoint(snapshot, vs.address(), vs.port(), alias, vs.certificates()));
            for (String id : vs.certificates()) {
                certificate(vs.address(), vs.port(), id, vs.certificates().size() > 1).ifPresent(certificates::add);
            }
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
