package io.github.danielstroehmann.tlm.kemp;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.math.BigInteger;
import java.nio.file.Path;
import java.security.cert.X509Certificate;
import java.util.List;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import com.digicert.tlm.workflows.WorkflowExecutionException;
import com.digicert.tlm.workflows.automation.dto.ValidateCertificateResponse;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;

import io.github.danielstroehmann.tlm.kemp.pki.FlowKeyStore;
import io.github.danielstroehmann.tlm.kemp.pki.Pem;
import io.github.danielstroehmann.tlm.kemp.testsupport.KempMock;
import io.github.danielstroehmann.tlm.kemp.testsupport.TestPki;

/** Integration: validateCertificate of the real plugin against a mock LoadMaster. */
@SuppressWarnings("unchecked")
@org.junit.jupiter.api.Timeout(60)
class PluginValidateTest {

    private static final TestPki.Ca CA = new TestPki.Ca("Validate");
    private static final X509Certificate PORTAL = CA.issue(TestPki.rsa(2048).getPublic(), "portal.example.com",
            new BigInteger("0A1B2C3D4E5F", 16));
    private static final X509Certificate SHOP = CA.issue(TestPki.rsa(2048).getPublic(), "shop.example.com",
            new BigInteger("7F00000000000001", 16));
    private static final X509Certificate WEBUI = CA.issue(TestPki.rsa(2048).getPublic(), "lm1.example.com", BigInteger.valueOf(4242));

    @TempDir
    Path tmp;
    private KempMock lm;
    private MockedPlugin plugin;

    @BeforeEach
    void start() {
        lm = new KempMock().defaults();
        lm.vs(2, "192.0.2.11", 443, "tcp", "sni", true, "portal shop")
                .vs(4, "192.0.2.13", 80, "tcp", "plain", false, null)
                .readcert("portal", TestPki.pem(PORTAL))
                .readcert("shop", TestPki.pem(SHOP))
                .readcert("web-ui", TestPki.pem(WEBUI));
        plugin = new MockedPlugin(lm, "validate-key", new FlowKeyStore(tmp));
    }

    @AfterEach
    void stop() {
        lm.close();
    }

    private static ObjectNode request(String ip, String port, String vsName, String serial) {
        ObjectNode n = MockedPlugin.MAPPER.createObjectNode();
        n.put("flowId", "11111111-2222-3333-4444-555555555555");
        n.put("ipAddress", ip);
        n.put("port", port);
        if (vsName != null) {
            n.put("virtualServerName", vsName);
        }
        n.put("certificateSerialNumber", serial);
        n.put("subjectDn", "CN=shop.example.com");
        n.put("unexpectedField", 1);
        return n;
    }

    @Test
    void returnsBoundCertificateBySerial() throws Exception {
        ValidateCertificateResponse<JsonNode> r = (ValidateCertificateResponse<JsonNode>) plugin
                .validateCertificate(request("192.0.2.11", "443", "default/sni", "7F00000000000001"));
        assertEquals(SHOP, Pem.parseCertificate(r.getCertificate()));
    }

    @Test
    void serialNotationIsTolerated() throws Exception {
        ValidateCertificateResponse<JsonNode> r = (ValidateCertificateResponse<JsonNode>) plugin
                .validateCertificate(request("192.0.2.11", "443", null, "00:0a:1b:2c:3d:4e:5f"));
        assertEquals(PORTAL, Pem.parseCertificate(r.getCertificate()));
    }

    @Test
    void managementTarget() throws Exception {
        ValidateCertificateResponse<JsonNode> r = (ValidateCertificateResponse<JsonNode>) plugin
                .validateCertificate(request(KempMock.MGMT_IP, "8443", null, new BigInteger("4242").toString(16)));
        assertEquals(WEBUI, Pem.parseCertificate(r.getCertificate()));
    }

    @Test
    void serialNotBoundFails() {
        WorkflowExecutionException e = assertThrows(WorkflowExecutionException.class,
                () -> plugin.validateCertificate(request("192.0.2.11", "443", null, "DEADBEEF")));
        assertTrue(e.getMessage().contains("DEADBEEF"), e.getMessage());
        assertTrue(e.getMessage().contains("not bound"), e.getMessage());
    }

    @Test
    void unknownEndpointFails() {
        WorkflowExecutionException e = assertThrows(WorkflowExecutionException.class,
                () -> plugin.validateCertificate(request("203.0.113.9", "443", null, "7F00000000000001")));
        assertTrue(e.getMessage().contains("No manageable endpoint"), e.getMessage());
    }

    @Test
    void unparseableCertificateIsSkipped() throws Exception {
        lm.readcert("portal", "garbage");
        ValidateCertificateResponse<JsonNode> r = (ValidateCertificateResponse<JsonNode>) plugin
                .validateCertificate(request("192.0.2.11", "443", null, "7F00000000000001"));
        assertEquals(SHOP, Pem.parseCertificate(r.getCertificate()));
    }

    @Test
    void validateNeverWrites() throws Exception {
        plugin.validateCertificate(request("192.0.2.11", "443", null, "7F00000000000001"));
        assertEquals(List.of(), lm.allWrites());
    }

    @Test
    void transportErrorFailsWorkflow() {
        lm.allHttp(401, "text/html", "<html>401</html>");
        assertThrows(WorkflowExecutionException.class,
                () -> plugin.validateCertificate(request("192.0.2.11", "443", null, "7F00000000000001")));
    }
}
