package io.github.danielstroehmann.tlm.kemp.loadmaster;

import java.util.Arrays;
import java.util.List;
import java.util.regex.Pattern;

import com.fasterxml.jackson.databind.JsonNode;

/**
 * A virtual service as reported by {@code listvs}.
 *
 * @param certificates       assigned certificate identifiers ({@code CertFile}); empty for the factory certificate
 * @param factoryCertificate SSL is on but only Kemp's built-in self-signed certificate is in use
 * @param subVs              SubVS of a content-switching service (no own address, certificate lives on the parent)
 */
public record VirtualService(String index, String address, int port, String protocol, String nickName, boolean ssl,
        List<String> certificates, boolean factoryCertificate, boolean subVs) {

    /** Kemp reports its built-in self-signed certificate as a single 32-hex-digit value in CertFile. */
    private static final Pattern FACTORY_CERT = Pattern.compile("^[0-9a-f]{32}$");

    public static VirtualService from(JsonNode n) {
        String certFile = n.path("CertFile").isTextual() ? n.path("CertFile").asText().trim() : "";
        List<String> certs = certFile.isEmpty() ? List.of() : Arrays.asList(certFile.split("\\s+"));
        boolean factory = certs.size() == 1 && FACTORY_CERT.matcher(certs.get(0)).matches();
        String address = n.path("VSAddress").isTextual() ? n.path("VSAddress").asText() : null;
        return new VirtualService(
                n.path("Index").asText(),
                address,
                n.path("VSPort").asInt(0),
                n.path("Protocol").asText("tcp"),
                n.path("NickName").isTextual() ? n.path("NickName").asText() : null,
                n.path("SSLAcceleration").asBoolean(false),
                factory ? List.of() : List.copyOf(certs),
                factory,
                address == null || n.path("MasterVSID").asInt(0) != 0);
    }

    /** Top-level service with TLS termination — the only kind the plugin manages (STATUS.md, case F). */
    public boolean manageable() {
        return !subVs && ssl && address != null;
    }

    public String endpoint() {
        return address + ":" + port;
    }
}
