package io.github.danielstroehmann.tlm.kemp.loadmaster;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Optional;
import java.util.Set;

import com.fasterxml.jackson.databind.JsonNode;

import io.github.danielstroehmann.tlm.kemp.client.KempApiException;
import io.github.danielstroehmann.tlm.kemp.client.KempClient;

/**
 * State of the LoadMaster needed to map TLM endpoints to Kemp objects, read once per plugin action.
 *
 * @param managementAddresses interface IPs (default interface first) plus the configured host if it is not one of them
 * @param adminCertificate    identifier of the web UI certificate, {@code null} if none is assigned
 * @param configuredHost      LoadMaster address from the connector configuration
 */
public record Snapshot(List<VirtualService> virtualServices, Set<String> acmeCertificates,
        List<String> managementAddresses, int wuiPort, String adminCertificate, String configuredHost) {

    /** Configured host taken from the last management address (for tests and simple callers). */
    public Snapshot(List<VirtualService> virtualServices, Set<String> acmeCertificates,
            List<String> managementAddresses, int wuiPort, String adminCertificate) {
        this(virtualServices, acmeCertificates, managementAddresses, wuiPort, adminCertificate,
                managementAddresses.get(managementAddresses.size() - 1));
    }

    /** Alias of the management endpoint in the inventory and in {@code virtualServerName}. */
    public static final String MANAGEMENT_ALIAS = "management";

    /** Kemp has no partitions; TLM expects one, so all endpoints are reported in this one. */
    public static final String PARTITION = "default";

    public static Snapshot load(KempClient client, String configuredHost) throws KempApiException {
        List<VirtualService> services = new ArrayList<>();
        for (JsonNode n : client.listVirtualServices()) {
            services.add(VirtualService.from(n));
        }
        List<String> addresses = new ArrayList<>(client.interfaceAddresses());
        if (!addresses.contains(configuredHost)) {
            addresses.add(configuredHost);
        }
        String admin = client.get("admincert");
        if (admin.isBlank() || admin.startsWith("No Admin Certificate")) {
            admin = null;
        }
        return new Snapshot(List.copyOf(services), Set.copyOf(client.listAcmeCertificates()), List.copyOf(addresses),
                Integer.parseInt(client.get("wuiport")), admin, configuredHost);
    }

    /** Web UI certificate can be taken over unless it is renewed by the LoadMaster's ACME client (case G). */
    public boolean adminCertificateManageable() {
        return adminCertificate == null || !acmeCertificates.contains(adminCertificate);
    }

    public List<VirtualService> manageable() {
        return virtualServices.stream().filter(VirtualService::manageable).toList();
    }

    /** IP of the default interface — TLM endpoints are IP based. */
    public String managementIp() {
        return managementAddresses.get(0);
    }

    /** NickName when it identifies the service uniquely, otherwise {@code address:port}. */
    public String alias(VirtualService vs) {
        String nick = vs.nickName();
        if (nick != null && !nick.isBlank() && !MANAGEMENT_ALIAS.equals(nick)
                && manageable().stream().filter(o -> nick.equals(o.nickName())).count() == 1) {
            return nick;
        }
        return vs.endpoint();
    }

    /**
     * Resolves the target of an install/validate request: by data IP and port first, then by the alias in
     * {@code virtualServerName} ({@code partition/alias} or just {@code alias}). The web UI is only chosen for the
     * explicit {@code management} alias, or for the management IP + web UI port when no virtual service lives there.
     */
    public Optional<Target> resolve(String ipAddress, String port, String virtualServerName) {
        String alias = virtualServerName == null ? "" : virtualServerName.substring(virtualServerName.lastIndexOf('/') + 1);
        if (MANAGEMENT_ALIAS.equals(alias)) {
            return Optional.of(new Target.Management());
        }
        Integer p = parsePort(port);
        if (ipAddress != null && p != null) {
            Optional<VirtualService> byEndpoint = manageable().stream()
                    .filter(vs -> ipAddress.equals(vs.address()) && vs.port() == p)
                    .min(Comparator.comparing(vs -> "tcp".equals(vs.protocol()) ? 0 : 1));
            if (byEndpoint.isPresent()) {
                return Optional.of(new Target.Vs(byEndpoint.get()));
            }
            boolean anyServiceThere = virtualServices.stream()
                    .anyMatch(vs -> ipAddress.equals(vs.address()) && vs.port() == p);
            boolean managementAddress = ipAddress.equals(managementIp()) || ipAddress.equals(configuredHost);
            if (p == wuiPort && managementAddress && !anyServiceThere) {
                return Optional.of(new Target.Management());
            }
        }
        if (!alias.isEmpty()) {
            return manageable().stream().filter(vs -> alias.equals(alias(vs))).findFirst().map(Target.Vs::new);
        }
        return Optional.empty();
    }

    private static Integer parsePort(String port) {
        try {
            return port == null ? null : Integer.valueOf(port.trim());
        } catch (NumberFormatException e) {
            return null;
        }
    }
}
