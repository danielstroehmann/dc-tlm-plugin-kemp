package io.github.danielstroehmann.tlm.kemp;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.UUID;
import java.util.stream.Stream;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import com.digicert.tlm.workflows.WorkflowExecutionException;
import com.digicert.tlm.workflows.automation.dto.GenerateCsrResponse;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;

import io.github.danielstroehmann.tlm.kemp.pki.FlowKeyStore;
import io.github.danielstroehmann.tlm.kemp.pki.Pem;
import io.github.danielstroehmann.tlm.kemp.testsupport.KempMock;
import io.github.danielstroehmann.tlm.kemp.testsupport.TestPki;

/** Integration: generateCsr + installCertificate of the real plugin against a mock LoadMaster. */
@SuppressWarnings("unchecked")
@org.junit.jupiter.api.Timeout(60)
class PluginInstallTest {

    private static final String KEY = "install-test-key";
    private static final TestPki.Ca CA = new TestPki.Ca("Install");
    private static final X509Certificate OLD_APP = CA.issue(TestPki.rsa(2048).getPublic(), "app.example.com", BigInteger.valueOf(1));
    private static final X509Certificate PORTAL = CA.issue(TestPki.rsa(2048).getPublic(), "portal.example.com",
            BigInteger.valueOf(2));
    private static final X509Certificate SHOP = CA.issue(TestPki.rsa(2048).getPublic(), "shop.example.com", BigInteger.valueOf(3));
    private static final X509Certificate WEBUI = CA.issue(TestPki.rsa(2048).getPublic(), "lm1.example.com", BigInteger.valueOf(4));
    private static final KeyPair NEW_KEYS = TestPki.rsa(2048);

    @TempDir
    Path tmp;
    private FlowKeyStore store;
    private KempMock lm;
    private MockedPlugin plugin;
    private String flow;

    @BeforeEach
    void start() {
        store = new FlowKeyStore(tmp.resolve("keys"));
        lm = new KempMock().defaults();
        lm.vs(1, "192.0.2.10", 443, "tcp", "app", true, "app-cert")
                .vs(2, "192.0.2.11", 443, "tcp", "sni", true, "portal shop")
                .vs(3, "192.0.2.12", 443, "tcp", "fresh", true, "0123456789abcdef0123456789abcdef")
                .vs(4, "192.0.2.13", 80, "tcp", "plain", false, null)
                .vs(5, "192.0.2.14", 443, "tcp", "letsencrypt", true, "acme-cert")
                .vs(6, "198.51.100.20", 8443, "tcp", "app-alt", true, "app-cert")
                .acme("acme-cert")
                .certificates("app-cert", "portal", "shop", "web-ui", "acme-cert")
                .readcert("app-cert", TestPki.pem(OLD_APP))
                .readcert("portal", TestPki.pem(PORTAL))
                .readcert("shop", TestPki.pem(SHOP))
                .readcert("web-ui", TestPki.pem(WEBUI));
        plugin = new MockedPlugin(lm, KEY, store);
        flow = UUID.randomUUID().toString();
    }

    @AfterEach
    void stop() {
        lm.close();
    }

    private X509Certificate storeKeyAndIssue(String cn) throws Exception {
        store.save(flow, NEW_KEYS.getPrivate(), KEY.toCharArray());
        return CA.issue(NEW_KEYS.getPublic(), cn, BigInteger.valueOf(System.nanoTime()), cn);
    }

    private ObjectNode install(String ip, Object port, String vsName, String chain, String thumbprint) {
        ObjectNode n = MockedPlugin.MAPPER.createObjectNode();
        n.put("flowId", flow);
        if (ip != null) {
            n.put("ipAddress", ip);
        }
        if (port instanceof Integer i) {
            n.put("port", i);
        } else if (port != null) {
            n.put("port", port.toString());
        }
        if (vsName != null) {
            n.put("virtualServerName", vsName);
        }
        n.put("certificateChain", chain);
        if (thumbprint != null) {
            n.put("currentCertificateThumbprint", thumbprint);
        }
        n.put("managementIp", KempMock.MGMT_IP);
        n.put("someFutureTlmField", "ignored");
        n.set("extendedRequest", MockedPlugin.MAPPER.createObjectNode().put("x", 1));
        return n;
    }

    private boolean keyStored() {
        return Files.exists(tmp.resolve("keys").resolve(flow));
    }

    // ---- end-to-end ----------------------------------------------------------------------------------------

    @Test
    void generateCsrThenInstallOnFactoryCertificateService() throws Exception {
        GenerateCsrResponse<JsonNode> csr = (GenerateCsrResponse<JsonNode>) plugin.generateCsr(
                MockedPlugin.csrRequest(flow, "CN=fresh.example.com,O=Example", "fresh.example.com", "RSA", "2048"));
        assertTrue(csr.getCsr().contains("BEGIN CERTIFICATE REQUEST"));
        assertTrue(keyStored());
        X509Certificate leaf = CA.issueFromCsr(csr.getCsr(), BigInteger.valueOf(777));

        plugin.installCertificate(install("192.0.2.12", "443", "default/fresh", TestPki.pem(leaf, CA.issuing, CA.root), ""));

        JsonNode inter = single(lm.writes("addintermediate"));
        assertEquals("tlm-ica-" + Pem.sha256(CA.issuing).substring(0, 16).toLowerCase(), inter.path("cert").asText());
        assertEquals(CA.issuing, Pem.parseCertificate(KempMock.decodeData(inter)));

        JsonNode add = single(lm.writes("addcert"));
        assertEquals("tlm-fresh.example.com", add.path("cert").asText());
        assertEquals("0", add.path("replace").asText());
        String uploaded = KempMock.decodeData(add);
        assertEquals(leaf, uploadedLeaf(add));
        assertEquals(1, uploaded.split("-----BEGIN CERTIFICATE-----", -1).length - 1, "only the leaf goes into addcert");
        assertEquals(1, uploaded.split("-----BEGIN PRIVATE KEY-----", -1).length - 1);
        assertTrue(Pem.keyMatches(uploadedKey(add, "RSA"), leaf), "uploaded private key must belong to the leaf");

        JsonNode modvs = single(lm.writes("modvs"));
        assertEquals("3", modvs.path("vs").asText());
        assertEquals("tlm-fresh.example.com", modvs.path("CertFile").asText(), "factory certificate is superseded");
        assertEquals(List.of(), lm.writes("set"));
        assertFalse(keyStored(), "key is deleted after a successful installation");
    }

    @Test
    void ecKeyEndToEnd() throws Exception {
        GenerateCsrResponse<JsonNode> csr = (GenerateCsrResponse<JsonNode>) plugin.generateCsr(
                MockedPlugin.csrRequest(flow, "CN=fresh.example.com", "", "EC", "384"));
        X509Certificate leaf = CA.issueFromCsr(csr.getCsr(), BigInteger.valueOf(778));
        plugin.installCertificate(install("192.0.2.12", 443, null, TestPki.pem(leaf, CA.issuing), null));
        assertEquals(leaf, uploadedLeaf(single(lm.writes("addcert"))));
        assertTrue(Pem.keyMatches(uploadedKey(single(lm.writes("addcert")), "EC"), leaf));
    }

    /**
     * Regression: PluginUtils.convertWrappedObject failed for the non-generic KempInstallRequest. An install JSON with
     * ipAddress/port/virtualServerName/certificateChain (plus unknown fields, numeric port) must deserialize and be processed.
     */
    @Test
    void regressionInstallRequestWithEndpointFieldsIsDeserializedAndProcessed() throws Exception {
        X509Certificate leaf = storeKeyAndIssue("app.example.com");
        ObjectNode req = install("192.0.2.10", 443, "default/app", TestPki.pem(leaf, CA.issuing), Pem.sha256(OLD_APP));
        assertNotNull(plugin.installCertificate(req));
        JsonNode add = single(lm.writes("addcert"));
        assertEquals("app-cert", add.path("cert").asText());
        assertEquals("1", add.path("replace").asText());
    }

    @Test
    void invalidRequestShapeIsWorkflowError() {
        ObjectNode req = MockedPlugin.MAPPER.createObjectNode();
        req.set("port", MockedPlugin.MAPPER.createObjectNode().put("nested", true));
        assertThrows(WorkflowExecutionException.class, () -> plugin.installCertificate(req));
    }

    // ---- renewal -------------------------------------------------------------------------------------------

    @Test
    void renewalReplacesIdentifierInPlace() throws Exception {
        X509Certificate leaf = storeKeyAndIssue("app.example.com");
        plugin.installCertificate(install("192.0.2.10", "443", "default/app", TestPki.pem(leaf, CA.issuing, CA.root),
                Pem.sha256(OLD_APP).toLowerCase()));
        JsonNode add = single(lm.writes("addcert"));
        assertEquals("app-cert", add.path("cert").asText());
        assertEquals("1", add.path("replace").asText());
        assertEquals(leaf, uploadedLeaf(add));
        assertEquals(List.of(), lm.writes("modvs"), "all services using app-cert pick up the new certificate");
        assertEquals(List.of(), lm.writes("set"));
    }

    @Test
    void renewalWithSha1ThumbprintWithColons() throws Exception {
        X509Certificate leaf = storeKeyAndIssue("app.example.com");
        String sha1 = String.join(":", Pem.sha1(OLD_APP).split("(?<=\\G..)"));
        plugin.installCertificate(install("198.51.100.20", "8443", null, TestPki.pem(leaf), sha1));
        assertEquals("app-cert", single(lm.writes("addcert")).path("cert").asText());
        assertEquals("1", single(lm.writes("addcert")).path("replace").asText());
    }

    @Test
    void renewalOfCertificateThatIsAlsoAdminCertReassignsIt() throws Exception {
        lm.get("admincert", "\"app-cert\"");
        X509Certificate leaf = storeKeyAndIssue("app.example.com");
        plugin.installCertificate(install("192.0.2.10", "443", null, TestPki.pem(leaf), Pem.sha256(OLD_APP)));
        List<JsonNode> writes = lm.allWrites();
        assertEquals(List.of("addcert", "set"), writes.stream().map(n -> n.path("cmd").asText()).toList());
        assertEquals("admincert", writes.get(1).path("param").asText());
        assertEquals("app-cert", writes.get(1).path("value").asText());
    }

    @Test
    void renewalOfAdminCertWithoutAllPermissionsIsRefusedBeforeWriting() throws Exception {
        lm.get("admincert", "\"app-cert\"").denyAdminCert();
        X509Certificate leaf = storeKeyAndIssue("app.example.com");
        WorkflowExecutionException e = assertThrows(WorkflowExecutionException.class, () -> plugin
                .installCertificate(install("192.0.2.10", "443", null, TestPki.pem(leaf, CA.issuing), Pem.sha256(OLD_APP))));
        assertTrue(e.getMessage().contains("All Permissions"), e.getMessage());
        assertEquals(List.of(), lm.allWrites());
        assertTrue(keyStored());
    }

    @Test
    void renewalOnSniServiceReplacesOnlyTheMatchingCertificate() throws Exception {
        X509Certificate leaf = storeKeyAndIssue("shop.example.com");
        plugin.installCertificate(install("192.0.2.11", "443", "default/sni", TestPki.pem(leaf), Pem.sha256(SHOP)));
        JsonNode add = single(lm.writes("addcert"));
        assertEquals("shop", add.path("cert").asText());
        assertEquals("1", add.path("replace").asText());
        assertEquals(List.of(), lm.writes("modvs"));
    }

    @Test
    void renewalDoesNotNeedVirtualServicesPermission() throws Exception {
        lm.deny("modvs");
        X509Certificate leaf = storeKeyAndIssue("app.example.com");
        plugin.installCertificate(install("192.0.2.10", "443", null, TestPki.pem(leaf), Pem.sha256(OLD_APP)));
        assertEquals("app-cert", single(lm.writes("addcert")).path("cert").asText());
    }

    // ---- new identifier ------------------------------------------------------------------------------------

    @Test
    void newCertificateOnSniServiceKeepsExistingEntriesInOrder() throws Exception {
        X509Certificate leaf = storeKeyAndIssue("blog.example.com");
        plugin.installCertificate(install("192.0.2.11", "443", null, TestPki.pem(leaf, CA.issuing), ""));
        JsonNode add = single(lm.writes("addcert"));
        assertEquals("tlm-blog.example.com", add.path("cert").asText());
        assertEquals("0", add.path("replace").asText());
        assertEquals("portal shop tlm-blog.example.com", single(lm.writes("modvs")).path("CertFile").asText());
    }

    @Test
    void thumbprintNotInUseOnTargetIsRefusedBeforeAnyWrite() throws Exception {
        X509Certificate leaf = storeKeyAndIssue("app.example.com");
        WorkflowExecutionException e = assertThrows(WorkflowExecutionException.class, () -> plugin
                .installCertificate(install("192.0.2.10", "443", null, TestPki.pem(leaf, CA.issuing), Pem.sha256(PORTAL))));
        assertTrue(e.getMessage().contains("not in use"), e.getMessage());
        assertTrue(e.getMessage().contains("nothing was changed"), e.getMessage());
        assertEquals(List.of(), lm.allWrites());
        assertTrue(keyStored());
    }

    @Test
    void firstInstallSupersedesCertificateForSameHostAtItsPosition() throws Exception {
        X509Certificate leaf = storeKeyAndIssue("shop.example.com");
        plugin.installCertificate(install("192.0.2.11", "443", null, TestPki.pem(leaf, CA.issuing), ""));
        assertEquals("portal tlm-shop.example.com", single(lm.writes("modvs")).path("CertFile").asText());
        assertEquals(List.of(), lm.writes("delcert"), "the superseded certificate is kept on the LoadMaster");
    }

    @Test
    void firstInstallSupersedesSingleCertificateForSameHost() throws Exception {
        X509Certificate leaf = storeKeyAndIssue("app.example.com");
        plugin.installCertificate(install("192.0.2.10", "443", null, TestPki.pem(leaf), null));
        assertEquals("tlm-app.example.com", single(lm.writes("modvs")).path("CertFile").asText());
        assertEquals("1", single(lm.writes("modvs")).path("vs").asText());
    }

    @Test
    void firstInstallUsesCurrentStateFromShowvsNotTheSnapshot() throws Exception {
        // Between listvs and modvs someone added a certificate on the LoadMaster: it must not be dropped.
        X509Certificate leaf = storeKeyAndIssue("blog.example.com");
        lm.on("showvs", "vs", "2", "{\"code\":200,\"Index\":2,\"VSAddress\":\"192.0.2.11\",\"VSPort\":\"443\","
                + "\"SSLAcceleration\":true,\"CertFile\":\"portal shop extra\",\"MasterVSID\":0,\"status\":\"ok\"}");
        plugin.installCertificate(install("192.0.2.11", "443", null, TestPki.pem(leaf), ""));
        assertEquals("portal shop extra tlm-blog.example.com", single(lm.writes("modvs")).path("CertFile").asText());
    }

    @Test
    void failedAssignmentRollsBackTheUpload() throws Exception {
        lm.on("modvs", KempMock.INVALID);
        X509Certificate leaf = storeKeyAndIssue("fresh.example.com");
        WorkflowExecutionException e = assertThrows(WorkflowExecutionException.class,
                () -> plugin.installCertificate(install("192.0.2.12", "443", null, TestPki.pem(leaf), "")));
        assertTrue(e.getMessage().contains("Invalid Format Input"), e.getMessage());
        assertEquals(List.of("addcert", "modvs", "delcert"), lm.allWrites().stream().map(n -> n.path("cmd").asText()).toList());
        assertEquals("tlm-fresh.example.com", single(lm.writes("delcert")).path("cert").asText());
        assertTrue(keyStored(), "key stays for a retry");
    }

    /** modvs reported an error (e.g. timeout) but the assignment went through: the certificate must not be deleted. */
    @Test
    void failedModvsWithAssignmentInPlaceIsNotRolledBack() throws Exception {
        lm.on("modvs", KempMock.INVALID);
        String before = "{\"code\":200,\"Index\":3,\"VSAddress\":\"192.0.2.12\",\"VSPort\":\"443\",\"SSLAcceleration\":true,"
                + "\"CertFile\":\"%s\",\"MasterVSID\":0,\"status\":\"ok\"}";
        java.util.function.Supplier<com.github.tomakehurst.wiremock.client.ScenarioMappingBuilder> showvsStub = () ->
                com.github.tomakehurst.wiremock.client.WireMock.post("/accessv2")
                        .withRequestBody(com.github.tomakehurst.wiremock.client.WireMock.matchingJsonPath("$.cmd",
                                com.github.tomakehurst.wiremock.client.WireMock.equalTo("showvs")))
                        .atPriority(1).inScenario("modvs-timeout");
        lm.server.stubFor(showvsStub.get().whenScenarioStateIs(com.github.tomakehurst.wiremock.stubbing.Scenario.STARTED)
                .willSetStateTo("assigned").willReturn(com.github.tomakehurst.wiremock.client.WireMock.okJson(
                        String.format(before, "0123456789abcdef0123456789abcdef"))));
        lm.server.stubFor(showvsStub.get().whenScenarioStateIs("assigned").willReturn(
                com.github.tomakehurst.wiremock.client.WireMock.okJson(String.format(before, "tlm-fresh.example.com"))));
        X509Certificate leaf = storeKeyAndIssue("fresh.example.com");
        WorkflowExecutionException e = assertThrows(WorkflowExecutionException.class,
                () -> plugin.installCertificate(install("192.0.2.12", "443", null, TestPki.pem(leaf), "")));
        assertTrue(e.getMessage().contains("Invalid Format Input"), "original error propagates: " + e.getMessage());
        assertEquals(2, lm.requests("showvs").size(), "state is re-read before rolling back");
        assertEquals(List.of(), lm.writes("delcert"), "an assigned certificate must never be deleted");
    }

    /** showvs failed before modvs was ever sent: the uploaded certificate is certainly unassigned and must be removed. */
    @Test
    void failedShowvsRollsBackTheUpload() throws Exception {
        lm.on("showvs", "vs", "3", "{\"code\":422,\"message\":\"Unknown VS\",\"status\":\"fail\"}");
        X509Certificate leaf = storeKeyAndIssue("fresh.example.com");
        assertThrows(WorkflowExecutionException.class,
                () -> plugin.installCertificate(install("192.0.2.12", "443", null, TestPki.pem(leaf), "")));
        assertEquals(List.of(), lm.writes("modvs"));
        assertEquals(List.of("addcert", "delcert"), lm.allWrites().stream().map(n -> n.path("cmd").asText()).toList(),
                "orphaned upload left on the LoadMaster");
    }

    @Test
    void failedRollbackStillReportsTheOriginalError() throws Exception {
        lm.on("modvs", KempMock.INVALID).on("delcert", KempMock.INVALID);
        X509Certificate leaf = storeKeyAndIssue("fresh.example.com");
        WorkflowExecutionException e = assertThrows(WorkflowExecutionException.class,
                () -> plugin.installCertificate(install("192.0.2.12", "443", null, TestPki.pem(leaf), "")));
        assertTrue(e.getMessage().contains("modvs"), e.getMessage());
    }

    @Test
    void existingIdentifierGetsTimestampSuffix() throws Exception {
        lm.certificates("app-cert", "TLM-WWW.example.com"); // Kemp identifiers compared case-insensitively
        X509Certificate leaf = storeKeyAndIssue("www.example.com");
        plugin.installCertificate(install("192.0.2.12", "443", null, TestPki.pem(leaf), null));
        String id = single(lm.writes("addcert")).path("cert").asText();
        assertTrue(id.matches("tlm-www\\.example\\.com-\\d{14}"), id);
        assertEquals(id, single(lm.writes("modvs")).path("CertFile").asText());
    }

    @Test
    void wildcardCommonNameIsSanitized() throws Exception {
        X509Certificate leaf = storeKeyAndIssue("*.example.com");
        plugin.installCertificate(install("192.0.2.12", "443", null, TestPki.pem(leaf), null));
        assertEquals("tlm-wildcard.example.com", single(lm.writes("addcert")).path("cert").asText());
    }

    // ---- H1: supersede only when all host names are covered -----------------------------------------------

    private void sharedVs() {
        X509Certificate certA = CA.issue(TestPki.rsa(2048).getPublic(), "a.example.com", BigInteger.valueOf(21),
                "a.example.com", "shared.example.com");
        X509Certificate certB = CA.issue(TestPki.rsa(2048).getPublic(), "b.example.com", BigInteger.valueOf(22), "b.example.com");
        lm.vs(7, "192.0.2.20", 443, "tcp", "multi", true, "cert-A cert-B")
                .readcert("cert-A", TestPki.pem(certA)).readcert("cert-B", TestPki.pem(certB));
    }

    @Test
    void partialOverlapIsInsertedBeforeTheOverlappingCertificate() throws Exception {
        sharedVs();
        store.save(flow, NEW_KEYS.getPrivate(), KEY.toCharArray());
        X509Certificate leaf = CA.issue(NEW_KEYS.getPublic(), "shared.example.com", BigInteger.valueOf(23), "shared.example.com");
        plugin.installCertificate(install("192.0.2.20", "443", null, TestPki.pem(leaf), ""));
        assertEquals("tlm-shared.example.com cert-A cert-B", single(lm.writes("modvs")).path("CertFile").asText());
    }

    @Test
    void certificateCoveringAllNamesReplacesInPlace() throws Exception {
        sharedVs();
        store.save(flow, NEW_KEYS.getPrivate(), KEY.toCharArray());
        X509Certificate leaf = CA.issue(NEW_KEYS.getPublic(), "a.example.com", BigInteger.valueOf(24), "shared.example.com",
                "a.example.com", "extra.example.com");
        plugin.installCertificate(install("192.0.2.20", "443", null, TestPki.pem(leaf), ""));
        assertEquals("tlm-a.example.com cert-B", single(lm.writes("modvs")).path("CertFile").asText());
    }

    @Test
    void wildcardCoveringSpecificCertificateReplacesIt() throws Exception {
        X509Certificate leaf = storeKeyAndIssue("*.example.com"); // SAN *.example.com covers shop/portal
        plugin.installCertificate(install("192.0.2.11", "443", null, TestPki.pem(leaf), ""));
        assertEquals("tlm-wildcard.example.com", single(lm.writes("modvs")).path("CertFile").asText(),
                "every completely covered entry is dropped");
    }

    @Test
    void specificCertificateGoesBeforeOverlappingWildcard() throws Exception {
        X509Certificate wildcard = CA.issue(TestPki.rsa(2048).getPublic(), "*.example.com", BigInteger.valueOf(25), "*.example.com");
        lm.vs(8, "192.0.2.21", 443, "tcp", "wild", true, "wild-cert").readcert("wild-cert", TestPki.pem(wildcard));
        X509Certificate leaf = storeKeyAndIssue("www.example.com");
        plugin.installCertificate(install("192.0.2.21", "443", null, TestPki.pem(leaf), ""));
        assertEquals("tlm-www.example.com wild-cert", single(lm.writes("modvs")).path("CertFile").asText(),
                "a specific name never replaces a wildcard, but must win for its host");
    }

    @Test
    void insertedBeforeFirstOverlappingEntryNotAtTheFront() throws Exception {
        X509Certificate certB = CA.issue(TestPki.rsa(2048).getPublic(), "b.example.com", BigInteger.valueOf(26), "b.example.com");
        X509Certificate certA = CA.issue(TestPki.rsa(2048).getPublic(), "a.example.com", BigInteger.valueOf(27),
                "a.example.com", "shared.example.com");
        X509Certificate wild = CA.issue(TestPki.rsa(2048).getPublic(), "*.example.com", BigInteger.valueOf(28), "*.example.com");
        lm.vs(9, "192.0.2.22", 443, "tcp", "order", true, "cert-B cert-A wild")
                .readcert("cert-B", TestPki.pem(certB)).readcert("cert-A", TestPki.pem(certA)).readcert("wild", TestPki.pem(wild));
        store.save(flow, NEW_KEYS.getPrivate(), KEY.toCharArray());
        X509Certificate leaf = CA.issue(NEW_KEYS.getPublic(), "shared.example.com", BigInteger.valueOf(29), "shared.example.com",
                "new.example.org");
        plugin.installCertificate(install("192.0.2.22", "443", null, TestPki.pem(leaf), ""));
        assertEquals("cert-B tlm-shared.example.com cert-A wild", single(lm.writes("modvs")).path("CertFile").asText());
    }

    @Test
    void newWildcardOverlappingSpecificIsInsertedBeforeIt() throws Exception {
        // *.example.com does not cover cert-A (a + a.b...) completely, but overlaps it.
        X509Certificate certA = CA.issue(TestPki.rsa(2048).getPublic(), "a.example.com", BigInteger.valueOf(30),
                "a.example.com", "deep.a.example.com");
        lm.vs(10, "192.0.2.23", 443, "tcp", "wild-new", true, "other cert-A")
                .readcert("other", TestPki.pem(CA.issue(TestPki.rsa(2048).getPublic(), "x.example.net", BigInteger.valueOf(31),
                        "x.example.net")))
                .readcert("cert-A", TestPki.pem(certA));
        X509Certificate leaf = storeKeyAndIssue("*.example.com");
        plugin.installCertificate(install("192.0.2.23", "443", null, TestPki.pem(leaf), ""));
        assertEquals("other tlm-wildcard.example.com cert-A", single(lm.writes("modvs")).path("CertFile").asText());
    }

    /**
     * First install on a service with the given entries (identifier to DNS names; {@code null} names = unreadable
     * certificate) and a new certificate for {@code newNames}; returns the CertFile sent with modvs.
     */
    private String firstInstall(java.util.LinkedHashMap<String, String[]> entries, String... newNames) throws Exception {
        BigInteger serial = BigInteger.valueOf(1000);
        for (var e : entries.entrySet()) {
            serial = serial.add(BigInteger.ONE);
            if (e.getValue() != null) {
                lm.readcert(e.getKey(), TestPki.pem(CA.issue(TestPki.rsa(2048).getPublic(), e.getValue()[0], serial, e.getValue())));
            }
        }
        lm.vs(20, "192.0.2.30", 443, "tcp", "rules", true, String.join(" ", entries.keySet()));
        store.save(flow, NEW_KEYS.getPrivate(), KEY.toCharArray());
        X509Certificate leaf = CA.issue(NEW_KEYS.getPublic(), "new-leaf.example.org", BigInteger.valueOf(999), newNames);
        plugin.installCertificate(install("192.0.2.30", "443", null, TestPki.pem(leaf), ""));
        return single(lm.writes("modvs")).path("CertFile").asText();
    }

    private static java.util.LinkedHashMap<String, String[]> entries(Object... idAndNames) {
        java.util.LinkedHashMap<String, String[]> m = new java.util.LinkedHashMap<>();
        for (int i = 0; i < idAndNames.length; i += 2) {
            m.put((String) idAndNames[i], (String[]) idAndNames[i + 1]);
        }
        return m;
    }

    private static String[] n(String... names) {
        return names;
    }

    @Test
    void coveredEntriesAreDroppedAndNewGoesBeforeFirstOverlap() throws Exception {
        // The case that motivated the rule: new-only is dropped, NEW goes before shop+new (overlap).
        assertEquals("tlm-new-leaf.example.org shop-new portal blog", firstInstall(entries(
                "shop-new", n("shop.example.com", "new.example.com"), "portal", n("portal.example.com"),
                "blog", n("blog.example.com"), "new-only", n("new.example.com")), "new.example.com"));
    }

    @Test
    void ruleExampleSharedOverlapGoesFirst() throws Exception {
        assertEquals("tlm-new-leaf.example.org A B", firstInstall(entries(
                "A", n("a.example.com", "shared.example.com"), "B", n("b.example.com")), "shared.example.com"));
    }

    @Test
    void ruleExampleAllCoveredLeavesOnlyNew() throws Exception {
        assertEquals("tlm-new-leaf.example.org", firstInstall(entries(
                "A", n("a.example.com"), "B", n("b.example.com")), "a.example.com", "b.example.com"));
    }

    @Test
    void ruleExampleCoveredEntryKeepsItsPosition() throws Exception {
        assertEquals("X tlm-new-leaf.example.org", firstInstall(entries(
                "X", n("x.example.com"), "A", n("a.example.com")), "a.example.com"));
    }

    @Test
    void ruleExampleSpecificBeforeWildcard() throws Exception {
        assertEquals("tlm-new-leaf.example.org W", firstInstall(entries("W", n("*.example.com")), "www.example.com"));
    }

    @Test
    void ruleExampleNoOverlapAppends() throws Exception {
        assertEquals("X Y tlm-new-leaf.example.org", firstInstall(entries(
                "X", n("x.example.com"), "Y", n("y.example.net")), "z.example.org"));
    }

    @Test
    void unreadableEntriesAreKeptAndNeverCountAsOverlap() throws Exception {
        assertEquals("broken tlm-new-leaf.example.org", firstInstall(entries(
                "broken", null, "A", n("a.example.com")), "a.example.com"));
    }

    @Test
    void unreadableOnlyListGetsNewAppended() throws Exception {
        assertEquals("broken1 broken2 tlm-new-leaf.example.org", firstInstall(entries(
                "broken1", null, "broken2", null), "a.example.com"));
    }

    // ---- renewal of Kemp's factory certificate (reported by the inventory) ---------------------------------

    private static final X509Certificate FACTORY_CERT = TestPki.selfSigned(TestPki.rsa(2048), "Kemp Factory Example");

    @Test
    void confirmedFactoryCertificateThumbprintIsAFirstInstall() throws Exception {
        plugin.served = (host, port) -> java.util.Optional.of(FACTORY_CERT);
        X509Certificate leaf = storeKeyAndIssue("fresh.example.com");
        plugin.installCertificate(install("192.0.2.12", "443", null, TestPki.pem(leaf, CA.issuing), Pem.sha256(FACTORY_CERT)));
        assertEquals(List.of("192.0.2.12:443"), plugin.lookups);
        assertEquals(List.of("addintermediate", "addcert", "modvs"),
                lm.allWrites().stream().map(n -> n.path("cmd").asText()).toList());
        assertEquals("0", single(lm.writes("addcert")).path("replace").asText());
        assertEquals("tlm-fresh.example.com", single(lm.writes("modvs")).path("CertFile").asText());
        assertFalse(keyStored());
    }

    @Test
    void factoryThumbprintMatchesInSha1WithColonsAndLowerCase() throws Exception {
        plugin.served = (host, port) -> java.util.Optional.of(FACTORY_CERT);
        X509Certificate leaf = storeKeyAndIssue("fresh.example.com");
        String sha1 = String.join(":", Pem.sha1(FACTORY_CERT).toLowerCase().split("(?<=\\G..)"));
        plugin.installCertificate(install("192.0.2.12", "443", null, TestPki.pem(leaf), sha1));
        assertEquals("tlm-fresh.example.com", single(lm.writes("modvs")).path("CertFile").asText());
    }

    @Test
    void unreadableFactoryCertificateIsRefusedBeforeAnyWrite() throws Exception {
        plugin.served = (host, port) -> java.util.Optional.empty();
        X509Certificate leaf = storeKeyAndIssue("fresh.example.com");
        WorkflowExecutionException e = assertThrows(WorkflowExecutionException.class, () -> plugin.installCertificate(
                install("192.0.2.12", "443", null, TestPki.pem(leaf, CA.issuing), Pem.sha256(FACTORY_CERT))));
        assertTrue(e.getMessage().contains("could not be confirmed"), e.getMessage());
        assertTrue(e.getMessage().contains("not readable from the sensor"), e.getMessage());
        assertEquals(List.of(), lm.allWrites());
        assertTrue(keyStored());
    }

    @Test
    void factoryThumbprintMismatchIsRefusedBeforeAnyWrite() throws Exception {
        X509Certificate otherFactory = TestPki.selfSigned(TestPki.rsa(2048), "Kemp Factory Example");
        plugin.served = (host, port) -> java.util.Optional.of(otherFactory);
        X509Certificate leaf = storeKeyAndIssue("fresh.example.com");
        WorkflowExecutionException e = assertThrows(WorkflowExecutionException.class, () -> plugin.installCertificate(
                install("192.0.2.12", "443", null, TestPki.pem(leaf, CA.issuing), Pem.sha256(FACTORY_CERT))));
        assertTrue(e.getMessage().contains("is no longer presented by 192.0.2.12:443"), e.getMessage());
        assertTrue(e.getMessage().contains("refresh the configuration in TLM"), e.getMessage());
        assertTrue(e.getMessage().contains("Nothing was changed."), e.getMessage());
        assertEquals(List.of("192.0.2.12:443"), plugin.lookups);
        assertEquals(List.of(), lm.allWrites());
        assertTrue(keyStored());
    }

    @Test
    void confirmedFactoryRenewalStillNeedsVirtualServicesPermission() throws Exception {
        lm.deny("modvs");
        plugin.served = (host, port) -> java.util.Optional.of(FACTORY_CERT);
        X509Certificate leaf = storeKeyAndIssue("fresh.example.com");
        WorkflowExecutionException e = assertThrows(WorkflowExecutionException.class, () -> plugin.installCertificate(
                install("192.0.2.12", "443", null, TestPki.pem(leaf, CA.issuing), Pem.sha256(FACTORY_CERT))));
        assertTrue(e.getMessage().contains("'Virtual Services'"), e.getMessage());
        assertEquals(List.of(), plugin.lookups, "a missing permission is reported without any TLS lookup");
        assertEquals(List.of(), lm.allWrites());
    }

    @Test
    void permissionCheckRunsBeforeTheFactoryConfirmation() throws Exception {
        lm.deny("modvs");
        plugin.served = (host, port) -> {
            throw new AssertionError("servedCertificate must not be called without the Virtual Services permission");
        };
        X509Certificate leaf = storeKeyAndIssue("fresh.example.com");
        WorkflowExecutionException e = assertThrows(WorkflowExecutionException.class, () -> plugin.installCertificate(
                install("192.0.2.12", "443", null, TestPki.pem(leaf), Pem.sha256(FACTORY_CERT))));
        assertTrue(e.getMessage().contains("'Virtual Services'"), e.getMessage());
        assertEquals(List.of(), lm.allWrites());
    }

    @Test
    void firstInstallWithoutThumbprintOnFactoryServiceNeedsNoLookup() throws Exception {
        X509Certificate leaf = storeKeyAndIssue("fresh.example.com");
        plugin.installCertificate(install("192.0.2.12", "443", null, TestPki.pem(leaf), ""));
        assertEquals(List.of(), plugin.lookups);
        assertEquals("tlm-fresh.example.com", single(lm.writes("modvs")).path("CertFile").asText());
    }

    @Test
    void unmatchedThumbprintWithOwnCertificateIsStillRefused() throws Exception {
        // Mixed list: factory value plus an own certificate - not a "factory only" service, so no lookup either.
        lm.vs(11, "192.0.2.24", 443, "tcp", "mixed", true, "0123456789abcdef0123456789abcdef app-cert");
        X509Certificate leaf = storeKeyAndIssue("app.example.com");
        WorkflowExecutionException e = assertThrows(WorkflowExecutionException.class, () -> plugin
                .installCertificate(install("192.0.2.24", "443", null, TestPki.pem(leaf), Pem.sha256(FACTORY_CERT))));
        assertTrue(e.getMessage().contains("not in use"), e.getMessage());
        assertEquals(List.of(), plugin.lookups);
        assertEquals(List.of(), lm.allWrites());
    }

    // ---- key family: an RSA/ECDSA pair keeps its other half -----------------------------------------------

    private String firstInstallWithKeyFamilies(java.security.KeyPair newKeys) throws Exception {
        X509Certificate rsa = CA.issue(TestPki.rsa(2048).getPublic(), "a.example.com", BigInteger.valueOf(301), "a.example.com");
        X509Certificate ec = CA.issue(TestPki.ec("secp256r1").getPublic(), "a.example.com", BigInteger.valueOf(302), "a.example.com");
        lm.vs(21, "192.0.2.31", 443, "tcp", "dual", true, "A_rsa A_ec")
                .readcert("A_rsa", TestPki.pem(rsa)).readcert("A_ec", TestPki.pem(ec));
        store.save(flow, newKeys.getPrivate(), KEY.toCharArray());
        X509Certificate leaf = CA.issue(newKeys.getPublic(), "a.example.com", BigInteger.valueOf(303), "a.example.com");
        plugin.installCertificate(install("192.0.2.31", "443", null, TestPki.pem(leaf), ""));
        return single(lm.writes("modvs")).path("CertFile").asText();
    }

    @Test
    void newRsaCertificateReplacesOnlyTheRsaHalf() throws Exception {
        assertEquals("tlm-a.example.com A_ec", firstInstallWithKeyFamilies(TestPki.rsa(2048)));
    }

    @Test
    void newEcCertificateReplacesOnlyTheEcHalf() throws Exception {
        assertEquals("tlm-a.example.com A_rsa", firstInstallWithKeyFamilies(TestPki.ec("secp256r1")));
    }

    // ---- leaf validation and key-bound retry ---------------------------------------------------------------

    @Test
    void expiredIssuedCertificateIsRefusedBeforeAnyWrite() throws Exception {
        store.save(flow, NEW_KEYS.getPrivate(), KEY.toCharArray());
        java.time.Instant now = java.time.Instant.now();
        X509Certificate expired = CA.issueCustom(NEW_KEYS.getPublic(), "app.example.com", now.minusSeconds(864000),
                now.minusSeconds(86400), false);
        WorkflowExecutionException e = assertThrows(WorkflowExecutionException.class, () -> plugin
                .installCertificate(install("192.0.2.10", "443", null, TestPki.pem(expired, CA.issuing), Pem.sha256(OLD_APP))));
        assertTrue(e.getMessage().contains("not currently valid"), e.getMessage());
        assertEquals(List.of(), lm.allWrites());
    }

    @Test
    void clientAuthOnlyCertificateIsRefused() throws Exception {
        store.save(flow, NEW_KEYS.getPrivate(), KEY.toCharArray());
        java.time.Instant now = java.time.Instant.now();
        X509Certificate client = CA.issueCustom(NEW_KEYS.getPublic(), "app.example.com", now.minusSeconds(60),
                now.plusSeconds(86400), false, org.bouncycastle.asn1.x509.KeyPurposeId.id_kp_clientAuth);
        assertThrows(WorkflowExecutionException.class, () -> plugin
                .installCertificate(install("192.0.2.10", "443", null, TestPki.pem(client), Pem.sha256(OLD_APP))));
        assertEquals(List.of(), lm.allWrites());
    }

    /** While the flow key exists, a package that merely contains the currently bound certificate must not end the flow. */
    @Test
    void packageWithOnlyTheBoundCertificateDoesNotCountWhileKeyExists() throws Exception {
        store.save(flow, NEW_KEYS.getPrivate(), KEY.toCharArray());
        WorkflowExecutionException e = assertThrows(WorkflowExecutionException.class,
                () -> plugin.installCertificate(install("192.0.2.10", "443", null, TestPki.pem(OLD_APP, CA.issuing), "")));
        assertTrue(e.getMessage().contains("does not match the private key"), e.getMessage());
        assertEquals(List.of(), lm.allWrites());
        assertTrue(keyStored());
    }

    @Test
    void packageContainingBoundAndNewCertificateInstallsTheNewOne() throws Exception {
        X509Certificate leaf = storeKeyAndIssue("app.example.com");
        plugin.installCertificate(install("192.0.2.10", "443", null, TestPki.pem(OLD_APP, leaf, CA.issuing), Pem.sha256(OLD_APP)));
        assertEquals(leaf, uploadedLeaf(single(lm.writes("addcert"))));
        assertFalse(keyStored());
    }

    // ---- certificate package download ----------------------------------------------------------------------

    @Test
    void untrustedCertificateLinkIsRefused() throws Exception {
        store.save(flow, NEW_KEYS.getPrivate(), KEY.toCharArray());
        try (KempMock download = new KempMock(true)) {
            ObjectNode req = install("192.0.2.10", "443", null, "", "");
            req.remove("certificateChain");
            req.put("certificateLink", download.httpsUrl() + "/package.zip");
            assertThrows(WorkflowExecutionException.class, () -> plugin.installCertificate(req));
            assertEquals(0, download.server.getAllServeEvents().size());
        }
        assertEquals(List.of(), lm.allWrites());
        assertTrue(keyStored());
    }

    // ---- intermediates -------------------------------------------------------------------------------------

    @Test
    void knownIntermediateIsNotUploadedAgain() throws Exception {
        lm.intermediates("existing-ica").readintermediate("existing-ica", TestPki.pem(CA.issuing));
        X509Certificate leaf = storeKeyAndIssue("app.example.com");
        plugin.installCertificate(install("192.0.2.10", "443", null, TestPki.pem(CA.root, leaf, CA.issuing), Pem.sha256(OLD_APP)));
        assertEquals(List.of(), lm.writes("addintermediate"));
        assertEquals(1, lm.writes("addcert").size());
    }

    @Test
    void intermediatePermissionNotNeededWhenIntermediatesAreKnown() throws Exception {
        lm.deny("addintermediate").intermediates("existing-ica").readintermediate("existing-ica", TestPki.pem(CA.issuing));
        X509Certificate leaf = storeKeyAndIssue("app.example.com");
        plugin.installCertificate(install("192.0.2.10", "443", null, TestPki.pem(leaf, CA.issuing), Pem.sha256(OLD_APP)));
        assertEquals(1, lm.writes("addcert").size());
    }

    @Test
    void unreadableExistingIntermediateDoesNotBlockInstall() throws Exception {
        lm.intermediates("broken").on("readintermediate", "cert", "broken",
                "{\"code\":422,\"message\":\"Unknown certificate\",\"status\":\"fail\"}");
        X509Certificate leaf = storeKeyAndIssue("app.example.com");
        plugin.installCertificate(install("192.0.2.10", "443", null, TestPki.pem(leaf, CA.issuing), Pem.sha256(OLD_APP)));
        assertEquals(1, lm.writes("addintermediate").size());
    }

    /**
     * A certificate package often contains the same certificate in several files (cert, chain, fullchain); obtainChain
     * concatenates them. Duplicates must neither upload the leaf as an intermediate nor upload a CA twice.
     */
    @Test
    void duplicateCertificatesInChainAreUploadedOnce() throws Exception {
        X509Certificate leaf = storeKeyAndIssue("app.example.com");
        String chain = TestPki.pem(leaf) + TestPki.pem(CA.issuing) + TestPki.pem(leaf, CA.issuing, CA.root);
        plugin.installCertificate(install("192.0.2.10", "443", null, chain, Pem.sha256(OLD_APP)));
        List<JsonNode> inter = lm.writes("addintermediate");
        for (JsonNode n : inter) {
            assertFalse(Pem.parseCertificate(KempMock.decodeData(n)).equals(leaf), "leaf uploaded as intermediate");
        }
        assertEquals(1, inter.size(), "issuing CA must be uploaded exactly once");
        assertEquals(CA.issuing, Pem.parseCertificate(KempMock.decodeData(inter.get(0))));
    }

    /** A CA in the package that did not sign the leaf (even with the right name) must not reach the shared store. */
    @Test
    void rogueCaInPackageIsNotUploaded() throws Exception {
        TestPki.Ca rogue = new TestPki.Ca("Install"); // same subject names, different keys
        TestPki.Ca unrelated = new TestPki.Ca("Unrelated");
        X509Certificate leaf = storeKeyAndIssue("app.example.com");
        String chain = TestPki.pem(rogue.issuing, unrelated.issuing, leaf, CA.issuing, rogue.root);
        plugin.installCertificate(install("192.0.2.10", "443", null, chain, Pem.sha256(OLD_APP)));
        List<JsonNode> inter = lm.writes("addintermediate");
        assertEquals(1, inter.size());
        assertEquals(CA.issuing, Pem.parseCertificate(KempMock.decodeData(inter.get(0))));
    }

    @Test
    void packageWithOnlyRogueCaUploadsNoIntermediate() throws Exception {
        TestPki.Ca rogue = new TestPki.Ca("Install");
        X509Certificate leaf = storeKeyAndIssue("app.example.com");
        plugin.installCertificate(install("192.0.2.10", "443", null, TestPki.pem(leaf, rogue.issuing), Pem.sha256(OLD_APP)));
        assertEquals(List.of(), lm.writes("addintermediate"));
        assertEquals(1, lm.writes("addcert").size());
    }

    @Test
    void twoLevelCaPathIsUploadedCompletely() throws Exception {
        TestPki.Issuer sub = CA.subordinate("Install Sub CA");
        store.save(flow, NEW_KEYS.getPrivate(), KEY.toCharArray());
        X509Certificate leaf = sub.issue(NEW_KEYS.getPublic(), "app.example.com", BigInteger.valueOf(99), "app.example.com");
        plugin.installCertificate(install("192.0.2.10", "443", null, TestPki.pem(CA.root, CA.issuing, leaf, sub.cert()),
                Pem.sha256(OLD_APP)));
        List<X509Certificate> uploaded = new java.util.ArrayList<>();
        for (JsonNode n : lm.writes("addintermediate")) {
            uploaded.add(Pem.parseCertificate(KempMock.decodeData(n)));
        }
        assertEquals(List.of(sub.cert(), CA.issuing), uploaded);
    }

    // ---- refusals ------------------------------------------------------------------------------------------

    @Test
    void acmeBoundServiceIsRefused() throws Exception {
        X509Certificate leaf = storeKeyAndIssue("acme.example.com");
        WorkflowExecutionException e = assertThrows(WorkflowExecutionException.class,
                () -> plugin.installCertificate(install("192.0.2.14", "443", null, TestPki.pem(leaf, CA.issuing), "")));
        assertTrue(e.getMessage().contains("ACME"), e.getMessage());
        assertEquals(List.of(), lm.allWrites());
        assertTrue(keyStored(), "key stays for a retry");
    }

    @Test
    void missingCertificateCreationPermission() throws Exception {
        lm.deny("addcert");
        X509Certificate leaf = storeKeyAndIssue("app.example.com");
        WorkflowExecutionException e = assertThrows(WorkflowExecutionException.class,
                () -> plugin.installCertificate(install("192.0.2.10", "443", null, TestPki.pem(leaf), Pem.sha256(OLD_APP))));
        assertTrue(e.getMessage().contains("'Certificate Creation'"), e.getMessage());
        assertEquals(List.of(), lm.allWrites());
    }

    @Test
    void missingIntermediatePermissionForUnknownCa() throws Exception {
        lm.deny("addintermediate");
        X509Certificate leaf = storeKeyAndIssue("app.example.com");
        WorkflowExecutionException e = assertThrows(WorkflowExecutionException.class, () -> plugin
                .installCertificate(install("192.0.2.10", "443", null, TestPki.pem(leaf, CA.issuing), Pem.sha256(OLD_APP))));
        assertTrue(e.getMessage().contains("'Intermediate Certificates'"), e.getMessage());
        assertEquals(List.of(), lm.allWrites());
    }

    /** A permission refusal must come before any change on the LoadMaster (no half-done installation). */
    @Test
    void missingVirtualServicesPermissionRefusesBeforeAnyChange() throws Exception {
        lm.deny("modvs");
        X509Certificate leaf = storeKeyAndIssue("fresh.example.com");
        WorkflowExecutionException e = assertThrows(WorkflowExecutionException.class,
                () -> plugin.installCertificate(install("192.0.2.12", "443", null, TestPki.pem(leaf, CA.issuing), "")));
        assertTrue(e.getMessage().contains("'Virtual Services'"), e.getMessage());
        assertEquals(List.of(), lm.writes("addcert"), "no certificate may be uploaded");
        assertEquals(List.of(), lm.allWrites(), "no change at all before refusing");
    }

    @Test
    void certificateNotMatchingFlowKeyIsRefused() throws Exception {
        store.save(flow, NEW_KEYS.getPrivate(), KEY.toCharArray());
        X509Certificate foreign = CA.issue(TestPki.rsa(2048).getPublic(), "app.example.com", BigInteger.TEN);
        WorkflowExecutionException e = assertThrows(WorkflowExecutionException.class,
                () -> plugin.installCertificate(install("192.0.2.10", "443", null, TestPki.pem(foreign, CA.issuing), "")));
        assertTrue(e.getMessage().contains("private key"), e.getMessage());
        assertEquals(List.of(), lm.allWrites());
        assertTrue(keyStored());
    }

    @Test
    void missingFlowKeyIsRefused() {
        X509Certificate leaf = CA.issue(NEW_KEYS.getPublic(), "app.example.com", BigInteger.TEN);
        WorkflowExecutionException e = assertThrows(WorkflowExecutionException.class,
                () -> plugin.installCertificate(install("192.0.2.10", "443", null, TestPki.pem(leaf), "")));
        assertTrue(e.getMessage().contains("generateCsr"), e.getMessage());
        assertEquals(List.of(), lm.allWrites());
    }

    @Test
    void pathTraversalFlowIdIsRefused() throws Exception {
        X509Certificate leaf = storeKeyAndIssue("app.example.com");
        ObjectNode req = install("192.0.2.10", "443", null, TestPki.pem(leaf), "");
        req.put("flowId", "../../etc");
        assertThrows(WorkflowExecutionException.class, () -> plugin.installCertificate(req));
        assertEquals(List.of(), lm.allWrites());
    }

    @Test
    void unknownEndpointIsRefused() throws Exception {
        X509Certificate leaf = storeKeyAndIssue("app.example.com");
        WorkflowExecutionException e = assertThrows(WorkflowExecutionException.class,
                () -> plugin.installCertificate(install("203.0.113.50", "443", "default/nope", TestPki.pem(leaf), "")));
        assertTrue(e.getMessage().contains("No manageable endpoint"), e.getMessage());
        assertEquals(List.of(), lm.allWrites());
    }

    @Test
    void serviceWithoutSslIsRefused() throws Exception {
        X509Certificate leaf = storeKeyAndIssue("plain.example.com");
        WorkflowExecutionException e = assertThrows(WorkflowExecutionException.class,
                () -> plugin.installCertificate(install("192.0.2.13", "80", "default/plain", TestPki.pem(leaf), "")));
        assertTrue(e.getMessage().contains("SSL"), e.getMessage());
        assertEquals(List.of(), lm.allWrites());
    }

    @Test
    void missingChainAndNonHttpsLinkIsRefused() throws Exception {
        store.save(flow, NEW_KEYS.getPrivate(), KEY.toCharArray());
        ObjectNode req = install("192.0.2.10", "443", null, "", "");
        req.put("certificateLink", "http://downloads.example.com/package.zip");
        WorkflowExecutionException e = assertThrows(WorkflowExecutionException.class, () -> plugin.installCertificate(req));
        assertTrue(e.getMessage().contains("https"), e.getMessage());
        req.remove("certificateLink");
        assertThrows(WorkflowExecutionException.class, () -> plugin.installCertificate(req));
        assertEquals(List.of(), lm.allWrites());
    }

    @Test
    void garbageChainIsRefused() throws Exception {
        store.save(flow, NEW_KEYS.getPrivate(), KEY.toCharArray());
        assertThrows(WorkflowExecutionException.class,
                () -> plugin.installCertificate(install("192.0.2.10", "443", null, "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----", "")));
        assertEquals(List.of(), lm.allWrites());
    }

    @Test
    void kempRejectingUploadFailsWorkflowAndKeepsKey() throws Exception {
        lm.on("addcert", KempMock.INVALID);
        lm.on("addcert", "cert", KempMock.PROBE, KempMock.INVALID);
        X509Certificate leaf = storeKeyAndIssue("app.example.com");
        WorkflowExecutionException e = assertThrows(WorkflowExecutionException.class,
                () -> plugin.installCertificate(install("192.0.2.10", "443", null, TestPki.pem(leaf), Pem.sha256(OLD_APP))));
        assertTrue(e.getMessage().contains("Invalid Format Input"), e.getMessage());
        assertTrue(keyStored());
    }

    // ---- web UI certificate (case H) -----------------------------------------------------------------------

    @Test
    void managementNewCertificateIsUploadedAndAssigned() throws Exception {
        X509Certificate leaf = storeKeyAndIssue("lm1.example.com");
        plugin.installCertificate(install(null, null, "default/management", TestPki.pem(leaf, CA.issuing), ""));
        List<JsonNode> writes = lm.allWrites();
        assertEquals(List.of("addintermediate", "addcert", "set"), writes.stream().map(n -> n.path("cmd").asText()).toList());
        assertEquals("tlm-lm1.example.com", writes.get(1).path("cert").asText());
        assertEquals("0", writes.get(1).path("replace").asText());
        assertEquals("admincert", writes.get(2).path("param").asText());
        assertEquals("tlm-lm1.example.com", writes.get(2).path("value").asText());
        assertEquals(List.of(), lm.writes("modvs"));
    }

    @Test
    void managementRenewalReplacesAndReassigns() throws Exception {
        X509Certificate leaf = storeKeyAndIssue("lm1.example.com");
        plugin.installCertificate(install(KempMock.MGMT_IP, "8443", null, TestPki.pem(leaf), Pem.sha256(WEBUI)));
        List<JsonNode> writes = lm.allWrites();
        assertEquals(List.of("addcert", "set"), writes.stream().map(n -> n.path("cmd").asText()).toList());
        assertEquals("web-ui", writes.get(0).path("cert").asText());
        assertEquals("1", writes.get(0).path("replace").asText());
        assertEquals("web-ui", writes.get(1).path("value").asText());
    }

    @Test
    void managementWithAcmeAdminCertIsRefused() throws Exception {
        lm.get("admincert", "\"acme-cert\"").readcert("acme-cert", TestPki.pem(WEBUI));
        X509Certificate leaf = storeKeyAndIssue("lm1.example.com");
        WorkflowExecutionException e = assertThrows(WorkflowExecutionException.class,
                () -> plugin.installCertificate(install(null, null, "management", TestPki.pem(leaf), "")));
        assertTrue(e.getMessage().contains("ACME"), e.getMessage());
        assertEquals(List.of(), lm.allWrites());
    }

    @Test
    void managementThumbprintNotMatchingAdminCertIsRefused() throws Exception {
        X509Certificate leaf = storeKeyAndIssue("lm1.example.com");
        WorkflowExecutionException e = assertThrows(WorkflowExecutionException.class, () -> plugin
                .installCertificate(install(null, null, "default/management", TestPki.pem(leaf, CA.issuing), Pem.sha256(PORTAL))));
        assertTrue(e.getMessage().contains("nothing was changed"), e.getMessage());
        assertEquals(List.of(), lm.allWrites());
    }

    @Test
    void managementWithoutAssignedAdminCertGetsNewIdentifier() throws Exception {
        lm.get("admincert", "\"No Admin Certificate assigned\"");
        X509Certificate leaf = storeKeyAndIssue("lm1.example.com");
        plugin.installCertificate(install(KempMock.MGMT_IP, "8443", null, TestPki.pem(leaf), ""));
        assertEquals(List.of("addcert", "set"), lm.allWrites().stream().map(n -> n.path("cmd").asText()).toList());
        assertEquals("tlm-lm1.example.com", single(lm.writes("set")).path("value").asText());
    }

    // ---- idempotent retry ----------------------------------------------------------------------------------

    @Test
    void retryAfterCompletedRenewalSucceedsWithoutKeyAndWithoutWrites() throws Exception {
        X509Certificate leaf = storeKeyAndIssue("app.example.com");
        ObjectNode req = install("192.0.2.10", "443", null, TestPki.pem(leaf, CA.issuing), Pem.sha256(OLD_APP));
        plugin.installCertificate(req);
        assertFalse(keyStored(), "key deleted after the first run");
        int writes = lm.allWrites().size();
        lm.readcert("app-cert", TestPki.pem(leaf)); // the LoadMaster now serves the renewed certificate

        assertNotNull(plugin.installCertificate(req));
        assertEquals(writes, lm.allWrites().size(), "retry must not change anything");
    }

    @Test
    void retryAfterCompletedFirstInstallSucceedsWithoutKey() throws Exception {
        X509Certificate leaf = CA.issue(NEW_KEYS.getPublic(), "fresh.example.com", BigInteger.valueOf(55), "fresh.example.com");
        lm.certFile(3, "tlm-fresh.example.com").readcert("tlm-fresh.example.com", TestPki.pem(leaf));
        assertNotNull(plugin.installCertificate(install("192.0.2.12", "443", null, TestPki.pem(leaf, CA.issuing), "")));
        assertEquals(List.of(), lm.allWrites());
    }

    @Test
    void retryRepairsMissingWebUiAssignment() throws Exception {
        X509Certificate leaf = CA.issue(NEW_KEYS.getPublic(), "lm1.example.com", BigInteger.valueOf(56), "lm1.example.com");
        lm.get("admincert", "\"No Admin Certificate assigned\"")
                .certificates("app-cert", "web-ui", "tlm-lm1.example.com")
                .readcert("tlm-lm1.example.com", TestPki.pem(leaf));
        assertNotNull(plugin.installCertificate(install(null, null, "default/management", TestPki.pem(leaf, CA.issuing), "")));
        assertEquals(List.of("set"), lm.allWrites().stream().map(n -> n.path("cmd").asText()).toList());
        assertEquals("tlm-lm1.example.com", single(lm.writes("set")).path("value").asText());
    }

    @Test
    void repairOfWebUiAssignmentNeedsAllPermissions() throws Exception {
        X509Certificate leaf = CA.issue(NEW_KEYS.getPublic(), "lm1.example.com", BigInteger.valueOf(57), "lm1.example.com");
        lm.get("admincert", "\"No Admin Certificate assigned\"").denyAdminCert()
                .certificates("tlm-lm1.example.com").readcert("tlm-lm1.example.com", TestPki.pem(leaf));
        assertThrows(WorkflowExecutionException.class,
                () -> plugin.installCertificate(install(null, null, "default/management", TestPki.pem(leaf), "")));
        assertEquals(List.of(), lm.allWrites());
    }

    @Test
    void caCertificateBoundOnTargetDoesNotCountAsInstalled() throws Exception {
        // The package's issuing CA happens to be bound on the service: that is not the issued certificate.
        lm.readcert("app-cert", TestPki.pem(CA.issuing));
        X509Certificate leaf = CA.issue(NEW_KEYS.getPublic(), "app.example.com", BigInteger.valueOf(58));
        WorkflowExecutionException e = assertThrows(WorkflowExecutionException.class,
                () -> plugin.installCertificate(install("192.0.2.10", "443", null, TestPki.pem(leaf, CA.issuing), "")));
        assertTrue(e.getMessage().contains("generateCsr"), "expected to need the key: " + e.getMessage());
    }

    @Test
    void keyCleanupFailureDoesNotFailTheInstall() throws Exception {
        org.junit.jupiter.api.Assumptions.assumeTrue(
                java.nio.file.FileSystems.getDefault().supportedFileAttributeViews().contains("posix"));
        X509Certificate leaf = storeKeyAndIssue("app.example.com");
        Path flowDir = tmp.resolve("keys").resolve(flow);
        java.nio.file.Files.setPosixFilePermissions(flowDir, java.nio.file.attribute.PosixFilePermissions.fromString("r-x------"));
        try {
            assertNotNull(plugin.installCertificate(install("192.0.2.10", "443", null, TestPki.pem(leaf), Pem.sha256(OLD_APP))));
            assertEquals(1, lm.writes("addcert").size());
        } finally {
            java.nio.file.Files.setPosixFilePermissions(flowDir, java.nio.file.attribute.PosixFilePermissions.fromString("rwx------"));
        }
    }

    @Test
    void managementWithoutAllPermissionsIsRefused() throws Exception {
        lm.denyAdminCert();
        X509Certificate leaf = storeKeyAndIssue("lm1.example.com");
        WorkflowExecutionException e = assertThrows(WorkflowExecutionException.class,
                () -> plugin.installCertificate(install(null, null, "default/management", TestPki.pem(leaf, CA.issuing), "")));
        assertTrue(e.getMessage().contains("All Permissions"), e.getMessage());
        assertEquals(List.of(), lm.allWrites());
    }

    // ---- generateCsr ---------------------------------------------------------------------------------------

    @Test
    void generateCsrRejectsPathTraversalFlowIdWithoutWritingOutside() throws Exception {
        assertThrows(WorkflowExecutionException.class, () -> plugin
                .generateCsr(MockedPlugin.csrRequest("../../etc", "CN=www.example.com", "", "RSA", "2048")));
        try (Stream<Path> s = Files.walk(tmp)) {
            assertEquals(List.of(tmp), s.toList());
        }
    }

    @Test
    void generateCsrRejectsWeakKeyAndInvalidDnsName() {
        assertThrows(WorkflowExecutionException.class, () -> plugin
                .generateCsr(MockedPlugin.csrRequest(flow, "CN=www.example.com", "", "RSA", "1024")));
        assertThrows(WorkflowExecutionException.class, () -> plugin
                .generateCsr(MockedPlugin.csrRequest(flow, "CN=www.example.com", "www.example.com,bad name", "RSA", "2048")));
        assertFalse(keyStored());
    }

    @Test
    void generateCsrRequiresApiKeyAsStorePassword() {
        KempLoadMasterPlugin noKey = new KempLoadMasterPlugin(MockedPlugin.config("lm.example.com", "443", ""), store);
        assertThrows(WorkflowExecutionException.class, () -> noKey
                .generateCsr(MockedPlugin.csrRequest(flow, "CN=www.example.com", "", "RSA", "2048")));
        assertFalse(keyStored());
    }

    @Test
    void storedKeyIsProtectedWithTheApiKey() throws Exception {
        plugin.generateCsr(MockedPlugin.csrRequest(flow, "CN=www.example.com", "", "RSA", "2048"));
        PrivateKey k = store.load(flow, KEY.toCharArray());
        assertNotNull(k);
        assertThrows(java.security.GeneralSecurityException.class, () -> store.load(flow, "other".toCharArray()));
    }

    private static X509Certificate uploadedLeaf(JsonNode addcert) throws Exception {
        String data = KempMock.decodeData(addcert);
        String end = "-----END CERTIFICATE-----";
        return Pem.parseCertificate(data.substring(0, data.indexOf(end) + end.length()));
    }

    private static PrivateKey uploadedKey(JsonNode addcert, String algorithm) throws Exception {
        String data = KempMock.decodeData(addcert);
        String b64 = data.substring(data.indexOf("-----BEGIN PRIVATE KEY-----") + 27, data.indexOf("-----END PRIVATE KEY-----"));
        return java.security.KeyFactory.getInstance(algorithm)
                .generatePrivate(new java.security.spec.PKCS8EncodedKeySpec(java.util.Base64.getMimeDecoder().decode(b64)));
    }

    private static JsonNode single(List<JsonNode> list) {
        assertEquals(1, list.size(), "expected exactly one request, got " + list);
        return list.get(0);
    }
}
