package io.github.danielstroehmann.tlm.kemp.client;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.google.common.util.concurrent.RateLimiter;

import kong.unirest.HttpResponse;
import kong.unirest.Unirest;
import kong.unirest.UnirestException;
import kong.unirest.UnirestInstance;
import lombok.extern.slf4j.Slf4j;

/**
 * Minimal client for the LoadMaster JSON API ({@code POST /accessv2}, firmware 7.2.50+).
 * <p>
 * Request bodies may contain certificates with private keys and the API key, so they are never logged.
 */
@Slf4j
public class KempClient implements AutoCloseable {

    /**
     * Kemp drops the connection when more than 30 API calls arrive within 3 seconds. The rate limiter may release
     * up to one second of saved permits as a burst, so the worst case is 4 x rate per 3 s: 7/s keeps it at 28.
     */
    static final double DEFAULT_CALLS_PER_SECOND = 7.0;

    /** Probe name that cannot collide with a real object; used to detect permissions without side effects. */
    static final String PROBE_NAME = "tlmprobe-does-not-exist";

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private final UnirestInstance http;
    private final String url;
    private final String apiKey;
    private final RateLimiter rateLimiter;

    KempClient(String baseUrl, String apiKey, double callsPerSecond) {
        this.url = baseUrl + "/accessv2";
        this.apiKey = apiKey;
        this.rateLimiter = callsPerSecond > 0 ? RateLimiter.create(callsPerSecond) : null;
        this.http = Unirest.spawnInstance();
        // Any management certificate is accepted on purpose (project decision, see STATUS.md): the plugin
        // must keep working with the factory self-signed cert, via IP, and after replacing the web UI cert itself.
        // The setting is confined to this Unirest instance.
        http.config().verifySsl(false).connectTimeout(10_000).socketTimeout(60_000);
    }

    /** @param host hostname, IPv4 address or bracketed IPv6 address — validated by the caller */
    public static KempClient connect(String host, int port, String apiKey) {
        return new KempClient("https://" + host + ":" + port, apiKey, DEFAULT_CALLS_PER_SECOND);
    }

    /** For tests against a mock LoadMaster (plain HTTP allowed); {@code callsPerSecond <= 0} disables throttling. */
    public static KempClient forBaseUrl(String baseUrl, String apiKey, double callsPerSecond) {
        return new KempClient(baseUrl, apiKey, callsPerSecond);
    }

    // ---- read ------------------------------------------------------------------------------------------

    /** Single value from {@code get param=...}; Kemp names the response field after the parameter. */
    public String get(String param) throws KempApiException {
        JsonNode r = call("get", Map.of("param", param));
        var fields = r.fields();
        while (fields.hasNext()) {
            var e = fields.next();
            if (e.getKey().equalsIgnoreCase(param)) {
                return e.getValue().asText();
            }
        }
        throw new KempApiException("Response to 'get " + param + "' has no value");
    }

    /** {@code null} when HA is not configured (Kemp answers that with a command failure). */
    public String haStatus() throws KempApiException {
        try {
            return get("hastatus");
        } catch (KempTransportException | KempPermissionDeniedException e) {
            throw e;
        } catch (KempApiException e) {
            return null;
        }
    }

    public JsonNode licenseInfo() throws KempApiException {
        return call("licenseinfo", Map.of());
    }

    /** Interface addresses without prefix length, default interface first. */
    public List<String> interfaceAddresses() throws KempApiException {
        List<String> result = new ArrayList<>();
        for (JsonNode iface : asArray(call("showiface", Map.of()).path("Interface"))) {
            String ip = iface.path("IPAddress").asText("").replaceFirst("/\\d+$", "");
            if (ip.isEmpty()) {
                continue;
            }
            if (iface.path("DefaultInterface").asBoolean(false)) {
                result.add(0, ip);
            } else {
                result.add(ip);
            }
        }
        return result;
    }

    /** All virtual services incl. SubVS, as returned by {@code listvs}. */
    public JsonNode listVirtualServices() throws KempApiException {
        return asArray(call("listvs", Map.of()).path("VS"));
    }

    public JsonNode showVirtualService(String index) throws KempApiException {
        return call("showvs", Map.of("vs", index));
    }

    public List<String> listCertificates() throws KempApiException {
        return names(call("listcert", Map.of()).path("cert"));
    }

    public String readCertificate(String identifier) throws KempApiException {
        return call("readcert", Map.of("cert", identifier)).path("certificate").asText();
    }

    public List<String> listIntermediates() throws KempApiException {
        return names(call("listintermediate", Map.of()).path("cert"));
    }

    public String readIntermediate(String identifier) throws KempApiException {
        return call("readintermediate", Map.of("cert", identifier)).path("certificate").asText();
    }

    /** Identifiers managed by the LoadMaster's own ACME client (Let's Encrypt and DigiCert accounts). */
    public Set<String> listAcmeCertificates() throws KempApiException {
        Set<String> result = new LinkedHashSet<>();
        for (String type : List.of("1", "2")) {
            try {
                for (JsonNode c : asArray(call("listacmecert", Map.of("acmetype", type)).path("Certificates"))) {
                    result.add(c.path("Identifier").asText());
                }
            } catch (KempTransportException | KempPermissionDeniedException e) {
                // An incomplete ACME list would disable the ACME safeguard — never ignore these.
                throw e;
            } catch (KempApiException e) {
                // "Account is not registered with LM" — no ACME certificates of this type.
                log.debug("listacmecert acmetype={}: {}", type, e.getMessage());
            }
        }
        return result;
    }

    // ---- write -----------------------------------------------------------------------------------------

    /** Uploads certificate + private key (one PEM file). {@code replace} keeps all virtual service bindings. */
    public void addCertificate(String identifier, String pem, boolean replace) throws KempApiException {
        call("addcert", Map.of("cert", identifier, "replace", replace ? "1" : "0", "data", base64(pem)));
    }

    public void deleteCertificate(String identifier) throws KempApiException {
        call("delcert", Map.of("cert", identifier));
    }

    public void addIntermediate(String identifier, String pem) throws KempApiException {
        call("addintermediate", Map.of("cert", identifier, "data", base64(pem)));
    }

    /** Replaces the complete certificate list of a virtual service (space separated identifiers). */
    public void setVirtualServiceCertificates(String index, List<String> identifiers) throws KempApiException {
        call("modvs", Map.of("vs", index, "CertFile", String.join(" ", identifiers)));
    }

    public void setAdminCertificate(String identifier) throws KempApiException {
        call("set", Map.of("param", "admincert", "value", identifier));
    }

    // ---- permission detection --------------------------------------------------------------------------
    //
    // Kemp checks the permission before the input, so a write command with deliberately invalid input answers
    // either "Permission denied" or a validation error — nothing is changed either way.

    public Capabilities probeCapabilities() throws KempApiException {
        String invalid = base64("not-a-certificate");
        return new Capabilities(
                allowed("addcert", Map.of("cert", PROBE_NAME, "replace", "0", "data", invalid)),
                allowed("addintermediate", Map.of("cert", PROBE_NAME, "data", invalid)),
                // No change parameters: even if this index existed, nothing would be modified.
                allowed("modvs", Map.of("vs", "2147483646")),
                probeAdminCertificate());
    }

    /**
     * "All Permissions" — the only Kemp permission that allows setting the web UI certificate. Should a firmware
     * ever accept the non-existent probe name, the previous web UI certificate is restored and the action fails.
     */
    public boolean probeAdminCertificate() throws KempApiException {
        String current = get("admincert");
        try {
            call("set", Map.of("param", "admincert", "value", PROBE_NAME));
        } catch (KempPermissionDeniedException e) {
            return false;
        } catch (KempTransportException e) {
            throw e;
        } catch (KempApiException e) {
            return true;
        }
        if (!current.isBlank() && !current.startsWith("No Admin Certificate")) {
            setAdminCertificate(current);
        }
        throw new KempApiException("LoadMaster accepted the admincert permission probe; web UI certificate '"
                + current + "' was restored - refusing to continue");
    }

    private boolean allowed(String cmd, Map<String, String> params) throws KempApiException {
        try {
            call(cmd, params);
            log.warn("Permission probe '{}' unexpectedly succeeded", cmd);
            return true;
        } catch (KempPermissionDeniedException e) {
            return false;
        } catch (KempTransportException e) {
            throw e;
        } catch (KempApiException e) {
            return true;
        }
    }

    // ---- transport -------------------------------------------------------------------------------------

    JsonNode call(String cmd, Map<String, String> params) throws KempApiException {
        ObjectNode body = MAPPER.createObjectNode();
        body.put("cmd", cmd);
        body.put("apikey", apiKey);
        params.forEach(body::put);

        if (rateLimiter != null) {
            rateLimiter.acquire();
        }
        HttpResponse<String> response;
        try {
            response = http.post(url).header("Content-Type", "application/json").body(body.toString()).asString();
        } catch (UnirestException e) {
            throw new KempTransportException("LoadMaster not reachable at " + url + ": " + rootMessage(e), e);
        }

        int status = response.getStatus();
        if (status == 401) {
            throw new KempTransportException("LoadMaster rejected the API key (HTTP 401)");
        }
        if (status == 404) {
            throw new KempTransportException("LoadMaster API not found (HTTP 404): check 'Enable API Interface' and the port");
        }
        if (status >= 500) {
            throw new KempTransportException("LoadMaster API error (HTTP " + status + ")");
        }
        JsonNode json;
        try {
            json = MAPPER.readTree(response.getBody());
        } catch (Exception e) {
            json = null;
        }
        if (json == null || !json.isObject()) {
            throw new KempTransportException("Unexpected non-JSON response from LoadMaster (HTTP " + status + ")");
        }
        if (!"ok".equals(json.path("status").asText())) {
            String message = json.path("message").asText("");
            if ("Permission denied".equals(message)) {
                throw new KempPermissionDeniedException(cmd);
            }
            throw new KempApiException("LoadMaster command '" + cmd + "' failed: " + message);
        }
        return json;
    }

    private static List<String> names(JsonNode array) {
        List<String> result = new ArrayList<>();
        asArray(array).forEach(n -> result.add(n.path("name").asText()));
        return result;
    }

    /** Lists may come back as a single object when they have one element; normalize to an array. */
    private static JsonNode asArray(JsonNode node) {
        if (node.isArray()) {
            return node;
        }
        var array = MAPPER.createArrayNode();
        if (node.isObject()) {
            array.add(node);
        }
        return array;
    }

    private static String base64(String text) {
        return Base64.getEncoder().encodeToString(text.getBytes(StandardCharsets.UTF_8));
    }

    private static String rootMessage(Throwable t) {
        while (t.getCause() != null) {
            t = t.getCause();
        }
        return t.getMessage();
    }

    @Override
    public void close() {
        http.shutDown();
    }

    /** Connectivity, authentication or server problem — the LoadMaster did not process the command. */
    public static class KempTransportException extends KempApiException {
        KempTransportException(String message) {
            super(message);
        }

        KempTransportException(String message, Throwable cause) {
            super(message, cause);
        }
    }
}
