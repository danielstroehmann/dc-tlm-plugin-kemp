package io.github.danielstroehmann.tlm.kemp;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.UUID;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import com.digicert.tlm.workflows.WorkflowExecutionException;
import com.digicert.tlm.workflows.automation.dto.GenerateCsrResponse;
import com.digicert.tlm.workflows.automation.dto.TestConnectionResponse;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;

import io.github.danielstroehmann.tlm.kemp.pki.FlowKeyStore;
import io.github.danielstroehmann.tlm.kemp.testsupport.KempMock;
import io.github.danielstroehmann.tlm.kemp.testsupport.TestPki;

/** The configured API key is stripped of surrounding whitespace for LoadMaster calls and the key store password. */
@Timeout(60)
@SuppressWarnings("unchecked")
class ApiKeyHandlingTest {

    private static final String KEY = "ApiKey-Strip-Test-0123456789";
    private static final TestPki.Ca CA = new TestPki.Ca("ApiKey");

    @TempDir
    Path tmp;

    /** The real client factory (https) against a mock that accepts only the exact key. */
    @ParameterizedTest
    @ValueSource(strings = { "  " + KEY + "  ", KEY + "\n", "\t" + KEY + "\r\n", " \t " + KEY + "\n\n", KEY })
    void keyWithSurroundingWhitespaceAuthenticates(String configured) throws Exception {
        try (KempMock lm = new KempMock(true).defaults().requireApiKey(KEY)) {
            KempLoadMasterPlugin plugin = new KempLoadMasterPlugin(
                    MockedPlugin.config("127.0.0.1", String.valueOf(lm.server.httpsPort()), configured), new FlowKeyStore(tmp));
            TestConnectionResponse<JsonNode> r = (TestConnectionResponse<JsonNode>) plugin.testConnection(null);
            assertTrue(r.isActive());
            List<String> keys = lm.requests("get").stream().map(n -> n.path("apikey").asText()).distinct().toList();
            assertEquals(List.of(KEY), keys, "only the stripped key is sent");
        }
    }

    @Test
    void mockReallyRejectsAWrongKey() throws Exception {
        // Guard for the test above: the strict mock does reject a key that differs inside.
        try (KempMock lm = new KempMock(true).defaults().requireApiKey(KEY)) {
            KempLoadMasterPlugin plugin = new KempLoadMasterPlugin(
                    MockedPlugin.config("127.0.0.1", String.valueOf(lm.server.httpsPort()), KEY + "x"), new FlowKeyStore(tmp));
            WorkflowExecutionException e = assertThrows(WorkflowExecutionException.class, () -> plugin.testConnection(null));
            assertTrue(e.getMessage().contains("401"), e.getMessage());
        }
    }

    @ParameterizedTest
    @ValueSource(strings = { "", " ", "\n", " \t\r\n ", " " })
    void whitespaceOnlyKeyIsRejectedAsMissing(String configured) {
        FlowKeyStore store = new FlowKeyStore(tmp.resolve("keys"));
        KempLoadMasterPlugin plugin = new KempLoadMasterPlugin(MockedPlugin.config("lm.example.com", "443", configured), store);
        WorkflowExecutionException e = assertThrows(WorkflowExecutionException.class, () -> plugin.testConnection(null));
        assertTrue(e.getMessage().contains("API key is required"), e.getMessage());
        WorkflowExecutionException csr = assertThrows(WorkflowExecutionException.class, () -> plugin
                .generateCsr(MockedPlugin.csrRequest(UUID.randomUUID().toString(), "CN=www.example.com", "", "RSA", "2048")));
        assertTrue(csr.getMessage().contains("API key is required"), csr.getMessage());
        assertFalse(Files.exists(tmp.resolve("keys")), "no key may be stored without an API key");
    }

    /** generateCsr and installCertificate run as separate processes; both must derive the same store password. */
    @ParameterizedTest
    @ValueSource(booleans = { true, false })
    void storedKeyDecryptsWhetherOrNotTheConfiguredKeyHasWhitespace(boolean whitespaceAtCsr) throws Exception {
        String padded = " " + KEY + "\n";
        FlowKeyStore store = new FlowKeyStore(tmp.resolve("keys"));
        String flow = UUID.randomUUID().toString();
        try (KempMock lm = new KempMock().defaults()) {
            lm.vs(3, "192.0.2.12", 443, "tcp", "fresh", true, "0123456789abcdef0123456789abcdef");
            MockedPlugin csrPlugin = new MockedPlugin(lm, whitespaceAtCsr ? padded : KEY, store);
            MockedPlugin installPlugin = new MockedPlugin(lm, whitespaceAtCsr ? KEY : padded, store);

            GenerateCsrResponse<JsonNode> csr = (GenerateCsrResponse<JsonNode>) csrPlugin
                    .generateCsr(MockedPlugin.csrRequest(flow, "CN=fresh.example.com", "", "RSA", "2048"));
            // The stored key is protected with exactly the stripped key.
            store.load(flow, KEY.toCharArray());
            assertThrows(java.security.GeneralSecurityException.class, () -> store.load(flow, padded.toCharArray()));

            X509Certificate leaf = CA.issueFromCsr(csr.getCsr(), BigInteger.valueOf(31));
            ObjectNode install = MockedPlugin.MAPPER.createObjectNode().put("flowId", flow).put("ipAddress", "192.0.2.12")
                    .put("port", "443").put("certificateChain", TestPki.pem(leaf, CA.issuing));
            installPlugin.installCertificate(install);
            assertEquals(1, lm.writes("addcert").size());
            assertEquals("tlm-fresh.example.com", lm.writes("addcert").get(0).path("cert").asText());
            assertFalse(store.exists(flow), "key deleted after the install");
        }
    }
}
