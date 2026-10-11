package io.github.danielstroehmann.tlm.kemp.testsupport;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.equalTo;
import static com.github.tomakehurst.wiremock.client.WireMock.matchingJsonPath;
import static com.github.tomakehurst.wiremock.client.WireMock.post;
import static com.github.tomakehurst.wiremock.client.WireMock.postRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.urlEqualTo;
import static com.github.tomakehurst.wiremock.core.WireMockConfiguration.options;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Map;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.github.tomakehurst.wiremock.WireMockServer;
import com.github.tomakehurst.wiremock.client.MappingBuilder;
import com.github.tomakehurst.wiremock.verification.LoggedRequest;

/**
 * WireMock-backed fake LoadMaster speaking the {@code POST /accessv2} JSON API. Stubs are routed by {@code cmd}
 * (and parameters) in the JSON body. Uses only documentation values (RFC 2606 / RFC 5737).
 */
public final class KempMock implements AutoCloseable {

    public static final String PATH = "/accessv2";
    /** Name the plugin uses for its side-effect-free permission probes. */
    public static final String PROBE = "tlmprobe-does-not-exist";
    public static final String MGMT_IP = "192.0.2.1";

    public static final String OK = "{\"code\":200,\"message\":\"Command Completed Successfully\",\"status\":\"ok\"}";
    public static final String INSTALLED = "{\"code\":200,\"message\":\"Certificate Successfully Installed\",\"status\":\"ok\"}";
    public static final String INVALID = "{\"code\":422,\"message\":\"Command Failed: Invalid Format Input\",\"status\":\"fail\"}";
    public static final String DENIED = "{\"code\":422,\"message\":\"Permission denied\",\"status\":\"fail\"}";

    private static final ObjectMapper MAPPER = new ObjectMapper();

    // Priorities: lower number wins. Denials override everything, specific matches override generic ones.
    private static final int DENY = 1;
    private static final int SPECIFIC = 5;
    private static final int GENERIC = 10;

    public final WireMockServer server;
    private final ArrayNode virtualServices = MAPPER.createArrayNode();

    public KempMock() {
        this(false);
    }

    public KempMock(boolean https) {
        // IPv4 loopback only and HTTP/1.1 only: avoids localhost/::1 resolution races and h2c upgrade handling.
        var config = options().bindAddress("127.0.0.1").dynamicPort().http2PlainDisabled(true).http2TlsDisabled(true)
                .containerThreads(20);
        server = new WireMockServer(https ? config.dynamicHttpsPort() : config);
        server.start();
    }

    public String baseUrl() {
        return "http://127.0.0.1:" + server.port();
    }

    public String httpsUrl() {
        return "https://127.0.0.1:" + server.httpsPort();
    }

    // ---- generic stubbing ----------------------------------------------------------------------------------

    private static MappingBuilder cmd(String cmd) {
        return post(urlEqualTo(PATH)).withRequestBody(matchingJsonPath("$.cmd", equalTo(cmd)));
    }

    private static com.github.tomakehurst.wiremock.client.ResponseDefinitionBuilder json(int status, String body) {
        return aResponse().withStatus(status).withHeader("Content-Type", "application/json").withBody(body);
    }

    public KempMock on(String cmd, String body) {
        server.stubFor(cmd(cmd).atPriority(GENERIC).willReturn(json(200, body)));
        return this;
    }

    public KempMock on(String cmd, String param, String value, String body) {
        server.stubFor(cmd(cmd).withRequestBody(matchingJsonPath("$." + param, equalTo(value))).atPriority(SPECIFIC)
                .willReturn(json(200, body)));
        return this;
    }

    public KempMock onHttp(String cmd, int status, String contentType, String body) {
        server.stubFor(cmd(cmd).atPriority(DENY)
                .willReturn(aResponse().withStatus(status).withHeader("Content-Type", contentType).withBody(body)));
        return this;
    }

    /** Every request (any cmd) gets this HTTP answer. */
    public KempMock allHttp(int status, String contentType, String body) {
        server.stubFor(post(urlEqualTo(PATH)).atPriority(DENY)
                .willReturn(aResponse().withStatus(status).withHeader("Content-Type", contentType).withBody(body)));
        return this;
    }

    public KempMock get(String param, String jsonValue) {
        return on("get", "param", param,
                "{\"code\":200,\"" + param + "\":" + jsonValue + ",\"status\":\"ok\"}");
    }

    /** Like a real LoadMaster: any request whose apikey is not exactly {@code key} gets HTTP 401 with an HTML body. */
    public KempMock requireApiKey(String key) {
        server.stubFor(post(urlEqualTo(PATH))
                .withRequestBody(matchingJsonPath("$.apikey", com.github.tomakehurst.wiremock.client.WireMock.not(equalTo(key))))
                .atPriority(DENY)
                .willReturn(aResponse().withStatus(401).withHeader("Content-Type", "text/html").withBody("<html>401</html>")));
        return this;
    }

    /** The API user lacks the permission for {@code cmd}: every call of it answers "Permission denied". */
    public KempMock deny(String cmd) {
        server.stubFor(cmd(cmd).atPriority(DENY).willReturn(json(200, DENIED)));
        return this;
    }

    /** {@code set admincert} denied (Kemp: only "All Permissions" may set it). */
    public KempMock denyAdminCert() {
        server.stubFor(cmd("set").withRequestBody(matchingJsonPath("$.param", equalTo("admincert"))).atPriority(DENY)
                .willReturn(json(200, DENIED)));
        return this;
    }

    // ---- LoadMaster state ----------------------------------------------------------------------------------

    /** A plausible standalone LoadMaster with all permissions, no certificates and no virtual services. */
    public KempMock defaults() {
        get("version", "\"7.2.63.2\"");
        get("wuiport", "8443");
        get("admincert", "\"web-ui\"");
        get("hostname", "\"lm1\"");
        on("get", "param", "hastatus", "{\"code\":422,\"message\":\"HA not configured\",\"status\":\"fail\"}");
        on("licenseinfo", "{\"code\":200,\"ApplianceModel\":\"VLM-200\",\"VlmPlatform\":\"KVM\",\"status\":\"ok\"}");
        on("showiface", "{\"code\":200,\"Interface\":["
                + "{\"Id\":1,\"IPAddress\":\"198.51.100.1/24\",\"DefaultInterface\":false},"
                + "{\"Id\":0,\"IPAddress\":\"" + MGMT_IP + "/24\",\"DefaultInterface\":true}],\"status\":\"ok\"}");
        on("listacmecert", "acmetype", "1", "{\"code\":422,\"message\":\"Account is not registered with LM\",\"status\":\"fail\"}");
        on("listacmecert", "acmetype", "2", "{\"code\":200,\"Certificates\":[],\"status\":\"ok\"}");
        certificates();
        intermediates();
        publishVirtualServices();
        // Unknown identifiers: Kemp answers with a command failure.
        on("readcert", "{\"code\":422,\"message\":\"Certificate not found\",\"status\":\"fail\"}");
        on("readintermediate", "{\"code\":422,\"message\":\"Certificate not found\",\"status\":\"fail\"}");
        on("showvs", "{\"code\":422,\"message\":\"Unknown VS\",\"status\":\"fail\"}");
        on("delcert", "{\"code\":200,\"message\":\"Command completed ok\",\"status\":\"ok\"}");
        // Writes succeed ...
        on("addcert", INSTALLED);
        on("addintermediate", INSTALLED);
        on("modvs", OK);
        on("set", OK);
        // ... but the probes carry invalid input and get a validation error, as on a real LoadMaster.
        on("addcert", "cert", PROBE, INVALID);
        on("addintermediate", "cert", PROBE, INVALID);
        on("modvs", "vs", "2147483646", "{\"code\":422,\"message\":\"Unknown VS\",\"status\":\"fail\"}");
        on("set", "value", PROBE, INVALID);
        return this;
    }

    public KempMock acme(String... identifiers) {
        ArrayNode certs = MAPPER.createArrayNode();
        for (String id : identifiers) {
            certs.addObject().put("Identifier", id);
        }
        return on("listacmecert", "acmetype", "2", "{\"code\":200,\"Certificates\":" + certs + ",\"status\":\"ok\"}");
    }

    public KempMock certificates(String... names) {
        return on("listcert", "{\"code\":200,\"cert\":" + names(names) + ",\"status\":\"ok\"}");
    }

    public KempMock intermediates(String... names) {
        return on("listintermediate", "{\"code\":200,\"cert\":" + names(names) + ",\"status\":\"ok\"}");
    }

    private static ArrayNode names(String... names) {
        ArrayNode arr = MAPPER.createArrayNode();
        for (String n : names) {
            arr.addObject().put("name", n).put("type", "RSA");
        }
        return arr;
    }

    public KempMock readcert(String id, String pem) {
        ObjectNode n = MAPPER.createObjectNode().put("code", 200).put("certificate", pem).put("status", "ok");
        return on("readcert", "cert", id, n.toString());
    }

    public KempMock readintermediate(String id, String pem) {
        ObjectNode n = MAPPER.createObjectNode().put("code", 200).put("certificate", pem).put("status", "ok");
        return on("readintermediate", "cert", id, n.toString());
    }

    /** Adds a top-level virtual service; {@code certFile} as Kemp reports it (space separated or 32-hex factory value). */
    public KempMock vs(int index, String address, int port, String protocol, String nickName, boolean ssl, String certFile) {
        ObjectNode n = virtualServices.addObject();
        n.put("Index", index);
        n.put("VSAddress", address);
        n.put("VSPort", String.valueOf(port));
        n.put("Protocol", protocol);
        if (nickName != null) {
            n.put("NickName", nickName);
        }
        n.put("SSLAcceleration", ssl);
        if (certFile != null) {
            n.put("CertFile", certFile);
        }
        n.put("MasterVSID", 0);
        return publishVirtualServices();
    }

    /** Changes the certificate list of a virtual service (as a completed modvs would). */
    public KempMock certFile(int index, String certFile) {
        for (JsonNode vs : virtualServices) {
            if (vs.path("Index").asInt() == index) {
                ((ObjectNode) vs).put("CertFile", certFile);
            }
        }
        return publishVirtualServices();
    }

    public KempMock subVs(int index, int masterIndex, String nickName, boolean ssl) {
        ObjectNode n = virtualServices.addObject();
        n.put("Index", index);
        n.put("VSPort", "0");
        n.put("Protocol", "tcp");
        n.put("NickName", nickName);
        n.put("SSLAcceleration", ssl);
        n.put("MasterVSID", masterIndex);
        return publishVirtualServices();
    }

    private KempMock publishVirtualServices() {
        for (JsonNode vs : virtualServices) {
            // showvs answers with the virtual service object at top level.
            ObjectNode shown = ((ObjectNode) vs).deepCopy();
            shown.put("code", 200).put("status", "ok");
            on("showvs", "vs", vs.path("Index").asText(), shown.toString());
        }
        return on("listvs", "{\"code\":200,\"VS\":" + virtualServices + ",\"status\":\"ok\"}");
    }

    // ---- verification --------------------------------------------------------------------------------------

    /** Bodies of all requests with this cmd, in order. */
    public List<JsonNode> requests(String cmd) {
        List<JsonNode> result = new ArrayList<>();
        for (LoggedRequest r : server.findAll(postRequestedFor(urlEqualTo(PATH)))) {
            JsonNode body = parse(r.getBodyAsString());
            if (cmd.equals(body.path("cmd").asText())) {
                result.add(body);
            }
        }
        return result;
    }

    /** Write requests of this cmd that are not permission probes (i.e. real changes). */
    public List<JsonNode> writes(String cmd) {
        List<JsonNode> result = new ArrayList<>();
        for (JsonNode n : requests(cmd)) {
            boolean probe = PROBE.equals(n.path("cert").asText()) || PROBE.equals(n.path("value").asText())
                    || "2147483646".equals(n.path("vs").asText());
            if (!probe) {
                result.add(n);
            }
        }
        return result;
    }

    /** All real changes (addcert, addintermediate, modvs, set, delcert) in request order. */
    public List<JsonNode> allWrites() {
        List<JsonNode> result = new ArrayList<>();
        for (LoggedRequest r : server.findAll(postRequestedFor(urlEqualTo(PATH)))) {
            JsonNode n = parse(r.getBodyAsString());
            String c = n.path("cmd").asText();
            boolean write = List.of("addcert", "addintermediate", "modvs", "set", "delcert").contains(c);
            boolean probe = PROBE.equals(n.path("cert").asText()) || PROBE.equals(n.path("value").asText())
                    || "2147483646".equals(n.path("vs").asText());
            if (write && !probe) {
                result.add(n);
            }
        }
        return result;
    }

    public List<String> rawBodies() {
        List<String> result = new ArrayList<>();
        for (LoggedRequest r : server.findAll(postRequestedFor(urlEqualTo(PATH)))) {
            result.add(r.getBodyAsString());
        }
        return result;
    }

    public static String decodeData(JsonNode request) {
        return new String(Base64.getDecoder().decode(request.path("data").asText()), StandardCharsets.UTF_8);
    }

    private static JsonNode parse(String body) {
        try {
            return MAPPER.readTree(body);
        } catch (Exception e) {
            return MAPPER.createObjectNode();
        }
    }

    public static ObjectNode object(Map<String, ?> fields) {
        ObjectNode n = MAPPER.createObjectNode();
        fields.forEach((k, v) -> n.set(k, MAPPER.valueToTree(v)));
        return n;
    }

    @Override
    public void close() {
        server.stop();
    }
}
