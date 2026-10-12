package io.github.danielstroehmann.tlm.kemp;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.math.BigInteger;
import java.nio.file.Path;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import com.digicert.tlm.workflows.WorkflowExecutionException;
import com.digicert.tlm.workflows.automation.dto.RefreshConfigurationResponse;
import com.digicert.tlm.workflows.automation.dto.RefreshConfigurationResponse.Certificate;
import com.digicert.tlm.workflows.automation.dto.RefreshConfigurationResponse.DataIpInfo;
import com.digicert.tlm.workflows.automation.dto.TestConnectionResponse;
import com.fasterxml.jackson.databind.JsonNode;

import io.github.danielstroehmann.tlm.kemp.pki.FlowKeyStore;
import io.github.danielstroehmann.tlm.kemp.testsupport.KempMock;
import io.github.danielstroehmann.tlm.kemp.testsupport.TestPki;

/** Integration: testConnection and refreshConfiguration of the real plugin against a mock LoadMaster. */
@SuppressWarnings("unchecked")
@org.junit.jupiter.api.Timeout(60)
class PluginConnectionAndInventoryTest {

    private static final String KEY = "inventory-test-key";
    private static final TestPki.Ca CA = new TestPki.Ca("Inventory");
    private static final X509Certificate APP = CA.issue(TestPki.rsa(2048).getPublic(), "app.example.com", BigInteger.valueOf(101),
            "app.example.com");
    private static final X509Certificate PORTAL = CA.issue(TestPki.rsa(2048).getPublic(), "portal.example.com",
            BigInteger.valueOf(102));
    private static final X509Certificate SHOP = CA.issue(TestPki.rsa(2048).getPublic(), "shop.example.net", BigInteger.valueOf(103));
    private static final X509Certificate WEBUI = CA.issue(TestPki.rsa(2048).getPublic(), "lm1.example.com", BigInteger.valueOf(104));

    @TempDir
    Path tmp;
    private KempMock lm;
    private MockedPlugin plugin;

    @BeforeEach
    void start() {
        lm = new KempMock().defaults();
        plugin = new MockedPlugin(lm, KEY, new FlowKeyStore(tmp));
    }

    @AfterEach
    void stop() throws Exception {
        lm.close();
        if (factoryServer != null) {
            factoryServer.close();
        }
    }

    /** Stands in for a virtual service presenting Kemp's built-in certificate (no network beyond loopback). */
    private io.github.danielstroehmann.tlm.kemp.testsupport.LocalServers.Tls factoryServer;

    // ---- testConnection ------------------------------------------------------------------------------------

    @Test
    void testConnectionActiveWithStandardPermissions() throws Exception {
        lm.denyAdminCert(); // "All Permissions" is optional
        TestConnectionResponse<JsonNode> r = (TestConnectionResponse<JsonNode>) plugin.testConnection(null);
        assertTrue(r.isActive());
        assertTrue(r.getErrors() == null || r.getErrors().isEmpty());
        assertEquals(List.of(), lm.allWrites(), "testConnection must not change anything");
    }

    @Test
    void testConnectionInactiveNamesMissingPermissions() throws Exception {
        lm.deny("addcert").deny("modvs");
        TestConnectionResponse<JsonNode> r = (TestConnectionResponse<JsonNode>) plugin.testConnection(null);
        assertFalse(r.isActive());
        assertEquals(1, r.getErrors().size());
        String msg = r.getErrors().get(0).getMessage();
        assertTrue(msg.contains("Certificate Creation"), msg);
        assertTrue(msg.contains("Virtual Services"), msg);
        assertFalse(msg.contains("Intermediate Certificates"), msg);
        assertTrue(msg.contains("7.2.63.2"), msg);
    }

    @Test
    void testConnectionWrongApiKey() {
        lm.allHttp(401, "text/html", "<html>401 Unauthorized</html>");
        WorkflowExecutionException e = assertThrows(WorkflowExecutionException.class, () -> plugin.testConnection(null));
        assertTrue(e.getMessage().contains("API key"), e.getMessage());
        assertFalse(e.getMessage().contains(KEY));
    }

    @Test
    void testConnectionApiDisabled() {
        lm.allHttp(404, "text/html", "<html>404</html>");
        WorkflowExecutionException e = assertThrows(WorkflowExecutionException.class, () -> plugin.testConnection(null));
        assertTrue(e.getMessage().contains("404"), e.getMessage());
    }

    @Test
    void realClientFactoryUsesHttpsAndAcceptsSelfSignedCertificate() throws Exception {
        try (KempMock https = new KempMock(true).defaults()) {
            KempLoadMasterPlugin real = new KempLoadMasterPlugin(
                    MockedPlugin.config(" 127.0.0.1 ", String.valueOf(https.server.httpsPort()), KEY), new FlowKeyStore(tmp));
            TestConnectionResponse<JsonNode> r = (TestConnectionResponse<JsonNode>) real.testConnection(null);
            assertTrue(r.isActive());
            assertEquals(KEY, https.requests("get").get(0).path("apikey").asText());
        }
    }

    @ParameterizedTest
    @ValueSource(strings = { "abc", "0", "65536", "-1", "443x" })
    void invalidPortIsRejected(String port) {
        KempLoadMasterPlugin real = new KempLoadMasterPlugin(MockedPlugin.config("lm.example.com", port, KEY),
                new FlowKeyStore(tmp));
        WorkflowExecutionException e = assertThrows(WorkflowExecutionException.class, () -> real.testConnection(null));
        assertTrue(e.getMessage().contains("port"), e.getMessage());
    }

    @Test
    void incompleteConfigurationIsRejected() {
        for (KempConfiguration c : List.of(MockedPlugin.config(null, "443", KEY), MockedPlugin.config(" ", "443", KEY))) {
            KempLoadMasterPlugin real = new KempLoadMasterPlugin(c, new FlowKeyStore(tmp));
            WorkflowExecutionException e = assertThrows(WorkflowExecutionException.class, () -> real.testConnection(null));
            assertTrue(e.getMessage().contains("host"), e.getMessage());
            assertThrows(WorkflowExecutionException.class, () -> real.refreshConfiguration(null));
        }
        for (KempConfiguration c : List.of(MockedPlugin.config("lm.example.com", "443", null),
                MockedPlugin.config("lm.example.com", "443", ""))) {
            KempLoadMasterPlugin real = new KempLoadMasterPlugin(c, new FlowKeyStore(tmp));
            WorkflowExecutionException e = assertThrows(WorkflowExecutionException.class, () -> real.testConnection(null));
            assertTrue(e.getMessage().contains("incomplete"), e.getMessage());
            assertThrows(WorkflowExecutionException.class, () -> real.refreshConfiguration(null));
        }
        assertThrows(WorkflowExecutionException.class,
                () -> new KempLoadMasterPlugin(null, new FlowKeyStore(tmp)).testConnection(null));
    }

    /** OWASP (SSRF / URL manipulation): the configured host must not be able to alter the request URL. */
    @ParameterizedTest
    @ValueSource(strings = { "https://lm.example.com", "lm.example.com:443", "a b", "::1", "2001:db8::1",
            "lm.example.com/accessv2", "lm.example.com?x=1", "lm.example.com#x", "lm.example.com@x", "-lm.example.com",
            "lm-.example.com", "lm..example.com", ".example.com", "[::1", "[lm.example.com]", "lm.example.com\nx",
            "lm_1.example.com" })
    void invalidHostIsRejectedBeforeAnyCall(String host) {
        KempLoadMasterPlugin real = new KempLoadMasterPlugin(MockedPlugin.config(host, "443", KEY), new FlowKeyStore(tmp));
        WorkflowExecutionException e = assertThrows(WorkflowExecutionException.class, () -> real.testConnection(null));
        assertTrue(e.getMessage().contains("host"), e.getMessage());
        // Also for the mock-backed plugin: the host is validated before the snapshot is read.
        MockedPlugin mocked = new MockedPlugin(lm, host, KEY, new FlowKeyStore(tmp));
        assertThrows(WorkflowExecutionException.class, () -> mocked.refreshConfiguration(null));
        assertThrows(WorkflowExecutionException.class, () -> mocked.validateCertificate(
                MockedPlugin.request(Map.of("ipAddress", "192.0.2.10", "port", "443", "certificateSerialNumber", "01"))));
        assertEquals(List.of(), lm.rawBodies(), "no LoadMaster call with an invalid host");
    }

    @Test
    void overlongHostIsRejected() {
        String host = String.join(".", "a".repeat(63), "b".repeat(63), "c".repeat(63), "d".repeat(60), "example.com");
        KempLoadMasterPlugin real = new KempLoadMasterPlugin(MockedPlugin.config(host, "443", KEY), new FlowKeyStore(tmp));
        assertThrows(WorkflowExecutionException.class, real::host);
    }

    @ParameterizedTest
    @ValueSource(strings = { "lm.example.com", "LM1", "lm-1.example.net", "192.0.2.1", "[::1]", "[2001:db8::10]",
            "  lm.example.com  " })
    void validHostsAreAccepted(String host) throws Exception {
        KempLoadMasterPlugin real = new KempLoadMasterPlugin(MockedPlugin.config(host, "443", KEY), new FlowKeyStore(tmp));
        assertEquals(host.trim(), real.host());
    }

    // ---- refreshConfiguration ------------------------------------------------------------------------------

    private void testbed() {
        try {
            factoryServer = new io.github.danielstroehmann.tlm.kemp.testsupport.LocalServers.Tls("Kemp Factory Example");
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
        lm.vs(1, "192.0.2.10", 443, "tcp", "app", true, "app-cert") // A: offload
                .vs(2, "198.51.100.20", 8443, "tcp", "app-alt", true, "app-cert") // C: shared certificate
                .vs(3, "192.0.2.11", 443, "tcp", "sni", true, "portal shop") // D: SNI
                .vs(4, "127.0.0.1", factoryServer.port(), "tcp", "fresh", true, "0123456789abcdef0123456789abcdef") // F
                .vs(5, "192.0.2.13", 80, "tcp", "plain", false, null) // no SSL
                .vs(6, "192.0.2.14", 443, "tcp", "cs", true, "portal") // E: content switching parent
                .subVs(7, 6, "cs-sub", true)
                .vs(8, "192.0.2.15", 443, "tcp", "letsencrypt", true, "acme-cert") // G: ACME
                .vs(9, "192.0.2.16", 443, "tcp", "dup", true, "shop")
                .vs(10, "192.0.2.17", 443, "tcp", "dup", true, "shop")
                .acme("acme-cert")
                .readcert("app-cert", TestPki.pem(APP))
                .readcert("portal", TestPki.pem(PORTAL))
                .readcert("shop", TestPki.pem(SHOP))
                .readcert("web-ui", TestPki.pem(WEBUI));
    }

    private static Map<String, DataIpInfo> byAlias(RefreshConfigurationResponse<JsonNode> r) {
        return r.getDataIpInfo().stream().collect(Collectors.toMap(DataIpInfo::getAlias, d -> d));
    }

    @Test
    void inventoryReportsManageableServicesAndSkipsOthers() throws Exception {
        testbed();
        RefreshConfigurationResponse<JsonNode> r = (RefreshConfigurationResponse<JsonNode>) plugin.refreshConfiguration(null);
        Map<String, DataIpInfo> eps = byAlias(r);
        assertEquals(java.util.Set.of("app", "app-alt", "sni", "fresh", "cs", "192.0.2.16:443", "192.0.2.17:443",
                "management"), eps.keySet());

        DataIpInfo app = eps.get("app");
        assertEquals("192.0.2.10", app.getDataIp());
        assertEquals(443, app.getPort());
        assertEquals("192.0.2.1", app.getManagementIp());
        assertEquals(1, app.getSslState());
        assertEquals("default", app.getPartition());
        assertEquals("443:app-cert", app.getPortWithCert());
        assertEquals("443:portal,shop", eps.get("sni").getPortWithCert());
        assertEquals(factoryServer.port() + ":kemp-factory-certificate-4", eps.get("fresh").getPortWithCert(),
                "factory certificate is reported under the reserved identifier");
        assertEquals("8443:web-ui", eps.get("management").getPortWithCert());
        assertEquals("192.0.2.1", eps.get("management").getDataIp());
        assertEquals(8443, eps.get("management").getPort());
    }

    @Test
    void inventoryCertificatesCarryPemCnSniAndIdentifier() throws Exception {
        testbed();
        RefreshConfigurationResponse<JsonNode> r = (RefreshConfigurationResponse<JsonNode>) plugin.refreshConfiguration(null);
        List<Certificate> certs = r.getCertificates();
        // app(1) + app-alt(1) + sni(2) + cs(1) + dup(1) + dup(1) + management(1)
        // ... + the factory certificate read from the handshake
        assertEquals(9, certs.size());
        Certificate factory = find(certs, "127.0.0.1:" + factoryServer.port(), "kemp-factory-certificate-4").orElseThrow();
        assertEquals(io.github.danielstroehmann.tlm.kemp.pki.Pem.toPem(factoryServer.certificate), factory.getCertificate());
        assertEquals("Kemp Factory Example", factory.getDomainName());
        assertFalse(factory.isSni());

        Certificate app = find(certs, "192.0.2.10:443", "app-cert").orElseThrow();
        assertEquals("192.0.2.10", app.getIpAddress());
        assertEquals(443, app.getPort());
        assertEquals("app.example.com", app.getDomainName());
        assertFalse(app.isSni());
        assertEquals(APP, io.github.danielstroehmann.tlm.kemp.pki.Pem.parseCertificate(app.getCertificate()));
        assertTrue(find(certs, "198.51.100.20:8443", "app-cert").isPresent(), "shared certificate reported per endpoint");

        Certificate portal = find(certs, "192.0.2.11:443", "portal").orElseThrow();
        assertTrue(portal.isSni());
        assertTrue(find(certs, "192.0.2.11:443", "shop").orElseThrow().isSni());
        assertEquals("lm1.example.com", find(certs, "192.0.2.1:8443", "web-ui").orElseThrow().getDomainName());
        assertTrue(certs.stream().noneMatch(c -> "acme-cert".equals(c.getServerParam())), "ACME certificates are skipped");
        assertTrue(certs.stream().noneMatch(c -> "192.0.2.13".equals(c.getIpAddress())));
        // Each certificate is read only once even if used several times.
        assertEquals(1, lm.requests("readcert").stream().filter(n -> "app-cert".equals(n.path("cert").asText())).count());
        assertEquals(List.of(), lm.allWrites(), "inventory must not change anything");
    }

    @Test
    void inventoryAutomationInfo() throws Exception {
        testbed();
        var info = ((RefreshConfigurationResponse<JsonNode>) plugin.refreshConfiguration(null)).getAutomationInfo();
        assertEquals("192.0.2.1", info.getManagementIp());
        assertEquals("lm1", info.getHostName());
        assertEquals("Kemp LoadMaster", info.getOsName());
        assertEquals("VLM-200", info.getOsFlavor());
        assertEquals("7.2.63.2", info.getOsVersion());
        assertEquals("KVM", info.getOsArch());
        assertEquals("disabled", info.getFips());
        assertEquals("", info.getPeerInfo());
        assertArrayEquals(new String[] { "default" }, info.getPartitions());
        assertEquals(List.of("192.0.2.10", "198.51.100.20", "192.0.2.11", "127.0.0.1", "192.0.2.14", "192.0.2.16",
                "192.0.2.17"), List.of(info.getDataIps()));
    }

    @Test
    void inventoryFipsAndHaPeer() throws Exception {
        lm.on("licenseinfo", "{\"code\":200,\"ApplianceModel\":\"VLM-FIPS\",\"VlmPlatform\":\"VMware\",\"status\":\"ok\"}");
        lm.get("hastatus", "\"active\"");
        var info = ((RefreshConfigurationResponse<JsonNode>) plugin.refreshConfiguration(null)).getAutomationInfo();
        assertEquals("enabled", info.getFips());
        assertEquals("192.0.2.1:ACTIVE", info.getPeerInfo());
    }

    @Test
    void factoryCertificateViaPluginSeam() throws Exception {
        X509Certificate factory = TestPki.selfSigned(TestPki.rsa(2048), "Kemp Factory Seam");
        plugin.served = (host, port) -> Optional.of(factory);
        lm.vs(4, "192.0.2.12", 443, "tcp", "fresh", true, "0123456789abcdef0123456789abcdef");
        RefreshConfigurationResponse<JsonNode> r = (RefreshConfigurationResponse<JsonNode>) plugin.refreshConfiguration(null);
        assertEquals(List.of("192.0.2.12:443"), plugin.lookups);
        assertEquals("443:kemp-factory-certificate-4", byAlias(r).get("fresh").getPortWithCert());
        assertEquals(io.github.danielstroehmann.tlm.kemp.pki.Pem.toPem(factory),
                find(r.getCertificates(), "192.0.2.12:443", "kemp-factory-certificate-4").orElseThrow().getCertificate());
    }

    @Test
    void unreachableFactoryServiceStaysUnsecured() throws Exception {
        int closed = io.github.danielstroehmann.tlm.kemp.testsupport.LocalServers.closedPort();
        lm.vs(4, "127.0.0.1", closed, "tcp", "fresh", true, "0123456789abcdef0123456789abcdef");
        RefreshConfigurationResponse<JsonNode> r = (RefreshConfigurationResponse<JsonNode>) plugin.refreshConfiguration(null);
        assertEquals(closed + ":", byAlias(r).get("fresh").getPortWithCert());
        assertTrue(r.getCertificates().stream().noneMatch(c -> c.getServerParam().startsWith("kemp-factory-certificate")));
    }

    @Test
    void managementEndpointOnlyWithAllPermissions() throws Exception {
        testbed();
        lm.denyAdminCert();
        RefreshConfigurationResponse<JsonNode> r = (RefreshConfigurationResponse<JsonNode>) plugin.refreshConfiguration(null);
        assertFalse(byAlias(r).containsKey("management"));
        assertTrue(r.getCertificates().stream().noneMatch(c -> "web-ui".equals(c.getServerParam())));
    }

    @Test
    void managementEndpointWithoutAdminCertificate() throws Exception {
        lm.get("admincert", "\"No Admin Certificate assigned\"");
        RefreshConfigurationResponse<JsonNode> r = (RefreshConfigurationResponse<JsonNode>) plugin.refreshConfiguration(null);
        assertEquals("8443:", byAlias(r).get("management").getPortWithCert());
        assertEquals(0, r.getCertificates().size());
    }

    @Test
    void unreadableCertificateIsSkippedNotReportedEmpty() throws Exception {
        lm.vs(1, "192.0.2.10", 443, "tcp", "app", true, "broken garbage good").readcert("good", TestPki.pem(APP))
                .readcert("garbage", "not a certificate")
                .on("readcert", "cert", "broken", "{\"code\":422,\"message\":\"Unknown certificate\",\"status\":\"fail\"}");
        RefreshConfigurationResponse<JsonNode> r = (RefreshConfigurationResponse<JsonNode>) plugin.refreshConfiguration(null);
        assertTrue(find(r.getCertificates(), "192.0.2.10:443", "broken").isEmpty());
        assertTrue(find(r.getCertificates(), "192.0.2.10:443", "garbage").isEmpty());
        assertTrue(r.getCertificates().stream().allMatch(c -> c.getCertificate() != null && c.getCertificate().contains("BEGIN")));
        assertEquals("app.example.com", find(r.getCertificates(), "192.0.2.10:443", "good").orElseThrow().getDomainName());
        assertEquals("443:broken,garbage,good", byAlias(r).get("app").getPortWithCert());
    }

    /** Only the re-encoded certificate may reach TLM, never surrounding text or other PEM blocks. */
    @Test
    void reportedPemIsReEncodedFromTheParsedCertificate() throws Exception {
        String raw = "Bag Attributes\n    friendlyName: app\nsubject=CN = app.example.com\n" + TestPki.pem(APP).replace("\n", "\r\n")
                + "trailing note\n";
        lm.vs(1, "192.0.2.10", 443, "tcp", "app", true, "app-cert").readcert("app-cert", raw);
        RefreshConfigurationResponse<JsonNode> r = (RefreshConfigurationResponse<JsonNode>) plugin.refreshConfiguration(null);
        Certificate c = find(r.getCertificates(), "192.0.2.10:443", "app-cert").orElseThrow();
        assertEquals(io.github.danielstroehmann.tlm.kemp.pki.Pem.toPem(APP), c.getCertificate());
        assertFalse(c.getCertificate().contains("Bag Attributes"));
        assertFalse(c.getCertificate().contains("trailing"));
    }

    @Test
    void additionalBlocksAfterTheCertificateDoNotReachTlm() throws Exception {
        String raw = TestPki.pem(APP) + TestPki.pem(PORTAL) + "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n";
        lm.vs(1, "192.0.2.10", 443, "tcp", "app", true, "app-cert").readcert("app-cert", raw);
        RefreshConfigurationResponse<JsonNode> r = (RefreshConfigurationResponse<JsonNode>) plugin.refreshConfiguration(null);
        for (Certificate c : r.getCertificates()) {
            assertFalse(c.getCertificate().contains("PRIVATE KEY"), "private key block reached TLM");
            assertEquals(1, c.getCertificate().split("-----BEGIN", -1).length - 1, "exactly one PEM block");
        }
    }

    @Test
    void unexpectedAdminProbeSuccessFailsRefreshAndRestores() {
        testbed();
        lm.on("set", "value", KempMock.PROBE, KempMock.OK);
        assertThrows(WorkflowExecutionException.class, () -> plugin.refreshConfiguration(null));
        assertEquals("web-ui", lm.writes("set").get(0).path("value").asText());
    }

    @Test
    void transportErrorWhileReadingCertificatesFailsRefresh() {
        lm.vs(1, "192.0.2.10", 443, "tcp", "app", true, "good").onHttp("readcert", 503, "text/html", "<html>503</html>");
        assertThrows(WorkflowExecutionException.class, () -> plugin.refreshConfiguration(null));
    }

    @Test
    void refreshOnlyProbesTheAdminCertificatePermission() throws Exception {
        testbed();
        plugin.refreshConfiguration(null);
        assertEquals(List.of(), lm.requests("addcert"));
        assertEquals(List.of(), lm.requests("addintermediate"));
        assertEquals(List.of(), lm.requests("modvs"));
        assertEquals(1, lm.requests("set").size());
        assertEquals(KempMock.PROBE, lm.requests("set").get(0).path("value").asText());
    }

    @Test
    void refreshWorksWithoutStandardPermissions() throws Exception {
        testbed();
        lm.deny("addcert").deny("addintermediate").deny("modvs");
        RefreshConfigurationResponse<JsonNode> r = (RefreshConfigurationResponse<JsonNode>) plugin.refreshConfiguration(null);
        assertTrue(byAlias(r).containsKey("app"));
    }

    @Test
    void acmeManagedWebUiCertificateIsNotOffered() throws Exception {
        testbed();
        lm.get("admincert", "\"acme-cert\"");
        RefreshConfigurationResponse<JsonNode> r = (RefreshConfigurationResponse<JsonNode>) plugin.refreshConfiguration(null);
        assertFalse(byAlias(r).containsKey("management"));
        assertTrue(r.getCertificates().stream().noneMatch(c -> "acme-cert".equals(c.getServerParam())));
    }

    @Test
    void refreshTransportErrorFailsWorkflow() {
        lm.onHttp("listvs", 401, "text/html", "<html>401</html>");
        WorkflowExecutionException e = assertThrows(WorkflowExecutionException.class, () -> plugin.refreshConfiguration(null));
        assertTrue(e.getMessage().startsWith("refreshConfiguration failed"), e.getMessage());
    }

    @Test
    void refreshPermissionDeniedFailsWorkflow() {
        lm.deny("listvs");
        assertThrows(WorkflowExecutionException.class, () -> plugin.refreshConfiguration(null));
    }

    /** If the ACME listing cannot be read, the refresh must fail rather than expose ACME-managed services. */
    @Test
    void acmeListingTransportErrorFailsRefresh() {
        testbed();
        lm.onHttp("listacmecert", 503, "text/html", "<html>503 Service Unavailable</html>");
        assertThrows(WorkflowExecutionException.class, () -> plugin.refreshConfiguration(null));
    }

    private static Optional<Certificate> find(List<Certificate> certs, String ipAndPort, String id) {
        return certs.stream().filter(c -> ipAndPort.equals(c.getIpAndPort()) && id.equals(c.getServerParam())).findFirst();
    }
}
