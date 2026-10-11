package io.github.danielstroehmann.tlm.kemp;

import java.util.Map;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;

import io.github.danielstroehmann.tlm.kemp.client.KempClient;
import io.github.danielstroehmann.tlm.kemp.pki.FlowKeyStore;
import io.github.danielstroehmann.tlm.kemp.testsupport.KempMock;

/** The real plugin, with only the client factory redirected to the WireMock LoadMaster (plain HTTP, no throttling). */
final class MockedPlugin extends KempLoadMasterPlugin {

    static final ObjectMapper MAPPER = new ObjectMapper();

    private final String baseUrl;
    private final String apiKey;

    MockedPlugin(KempMock lm, String apiKey, FlowKeyStore store) {
        this(lm, KempMock.MGMT_IP, apiKey, store);
    }

    MockedPlugin(KempMock lm, String host, String apiKey, FlowKeyStore store) {
        super(config(host, "8443", apiKey), store);
        this.baseUrl = lm.baseUrl();
        this.apiKey = apiKey;
    }

    static KempConfiguration config(String host, String port, String apiKey) {
        KempConfiguration c = new KempConfiguration();
        c.setManagementHost(host);
        c.setManagementPort(port);
        c.setApiKey(apiKey);
        return c;
    }

    @Override
    KempClient openClient() {
        return KempClient.forBaseUrl(baseUrl, apiKey, 0);
    }

    static ObjectNode request(Map<String, ?> fields) {
        ObjectNode n = MAPPER.createObjectNode();
        fields.forEach((k, v) -> n.set(k, MAPPER.valueToTree(v)));
        return n;
    }

    static ObjectNode csrRequest(String flowId, String subjectDn, String dnsNames, String keyAlgorithm, String keySize) {
        ObjectNode n = MAPPER.createObjectNode();
        n.put("flowId", flowId);
        n.put("subjectDn", subjectDn);
        n.put("dnsNames", dnsNames);
        n.put("keyAlgorithm", keyAlgorithm);
        n.put("keySize", keySize);
        n.put("signatureAlgorithm", "sha256");
        n.put("certificateProfileName", "unknown-field-tolerated");
        return n;
    }
}
