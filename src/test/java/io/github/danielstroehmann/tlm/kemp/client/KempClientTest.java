package io.github.danielstroehmann.tlm.kemp.client;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.net.ServerSocket;
import java.util.List;
import java.util.Set;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import com.fasterxml.jackson.databind.JsonNode;
import com.github.tomakehurst.wiremock.verification.LoggedRequest;

import io.github.danielstroehmann.tlm.kemp.client.KempClient.KempTransportException;
import io.github.danielstroehmann.tlm.kemp.testsupport.KempMock;

@org.junit.jupiter.api.Timeout(30)
class KempClientTest {

    private static final String KEY = "Zx9-SECRET-APIKEY-4711";
    private static final String HTML = "<html><body>Unauthorized</body></html>";

    private KempMock lm;
    private KempClient client;

    @BeforeEach
    void start() {
        lm = new KempMock().defaults();
        client = KempClient.forBaseUrl(lm.baseUrl(), KEY, 0);
    }

    @AfterEach
    void stop() {
        client.close();
        lm.close();
    }

    // ---- request format --------------------------------------------------------------------------------

    @Test
    void sendsJsonBodyWithCmdApiKeyAndParams() throws Exception {
        client.get("version");
        List<LoggedRequest> all = lm.server.getAllServeEvents().stream().map(e -> e.getRequest()).toList();
        assertEquals(1, all.size());
        LoggedRequest r = all.get(0);
        assertEquals("/accessv2", r.getUrl());
        assertEquals("POST", r.getMethod().getName());
        assertTrue(r.getHeader("Content-Type").startsWith("application/json"));
        JsonNode body = lm.requests("get").get(0);
        assertEquals("get", body.path("cmd").asText());
        assertEquals(KEY, body.path("apikey").asText());
        assertEquals("version", body.path("param").asText());
    }

    // ---- reads ---------------------------------------------------------------------------------------------

    @Test
    void getReturnsStringAndNumericValues() throws Exception {
        assertEquals("7.2.63.2", client.get("version"));
        assertEquals("8443", client.get("wuiport"));
    }

    @Test
    void getMatchesResponseFieldCaseInsensitively() throws Exception {
        lm.on("get", "param", "hostname", "{\"code\":200,\"HostName\":\"lm1\",\"status\":\"ok\"}");
        assertEquals("lm1", client.get("hostname"));
    }

    @Test
    void getWithoutValueFails() {
        lm.on("get", "param", "hostname", "{\"code\":200,\"status\":\"ok\"}");
        KempApiException e = assertThrows(KempApiException.class, () -> client.get("hostname"));
        assertFalse(e instanceof KempTransportException);
    }

    @Test
    void haStatusIsNullWithoutHa() throws Exception {
        assertNull(client.haStatus());
    }

    @Test
    void haStatusPermissionDeniedPropagates() {
        lm.deny("get");
        assertThrows(KempPermissionDeniedException.class, () -> client.haStatus());
    }

    @Test
    void haStatusTransportErrorPropagates() {
        lm.allHttp(401, "text/html", HTML);
        assertThrows(KempTransportException.class, () -> client.haStatus());
    }

    @Test
    void interfaceAddressesPutDefaultFirstAndStripPrefix() throws Exception {
        assertEquals(List.of("192.0.2.1", "198.51.100.1"), client.interfaceAddresses());
    }

    @Test
    void listsAndReadsCertificates() throws Exception {
        lm.certificates("app-cert", "web-ui").intermediates("ica-1").readcert("app-cert", "PEM-A")
                .readintermediate("ica-1", "PEM-I");
        assertEquals(List.of("app-cert", "web-ui"), client.listCertificates());
        assertEquals(List.of("ica-1"), client.listIntermediates());
        assertEquals("PEM-A", client.readCertificate("app-cert"));
        assertEquals("PEM-I", client.readIntermediate("ica-1"));
        assertEquals("app-cert", lm.requests("readcert").get(0).path("cert").asText());
    }

    @Test
    void acmeCertificatesFromBothAccountTypes() throws Exception {
        lm.on("listacmecert", "acmetype", "1",
                "{\"code\":200,\"Certificates\":[{\"Identifier\":\"le-cert\"}],\"status\":\"ok\"}");
        lm.acme("dc-cert");
        assertEquals(Set.of("le-cert", "dc-cert"), client.listAcmeCertificates());
    }

    @Test
    void acmeAccountNotRegisteredMeansNone() throws Exception {
        assertEquals(Set.of(), client.listAcmeCertificates());
    }

    @Test
    void acmeTransportErrorPropagates() {
        lm.onHttp("listacmecert", 401, "text/html", HTML);
        assertThrows(KempTransportException.class, () -> client.listAcmeCertificates());
    }

    // ---- writes --------------------------------------------------------------------------------------------

    @Test
    void addCertificateSendsBase64PemAndReplaceFlag() throws Exception {
        client.addCertificate("tlm-www.example.com", "PEM\nDATA", false);
        client.addCertificate("app-cert", "OTHER", true);
        List<JsonNode> writes = lm.writes("addcert");
        assertEquals("tlm-www.example.com", writes.get(0).path("cert").asText());
        assertEquals("0", writes.get(0).path("replace").asText());
        assertEquals("PEM\nDATA", KempMock.decodeData(writes.get(0)));
        assertEquals("1", writes.get(1).path("replace").asText());
    }

    @Test
    void addIntermediateModVsAndSetAdminCert() throws Exception {
        client.addIntermediate("tlm-ica-0123", "ICA");
        client.setVirtualServiceCertificates("4", List.of("a", "b", "c"));
        client.setAdminCertificate("web-ui");
        assertEquals("ICA", KempMock.decodeData(lm.writes("addintermediate").get(0)));
        JsonNode modvs = lm.writes("modvs").get(0);
        assertEquals("4", modvs.path("vs").asText());
        assertEquals("a b c", modvs.path("CertFile").asText());
        JsonNode set = lm.writes("set").get(0);
        assertEquals("admincert", set.path("param").asText());
        assertEquals("web-ui", set.path("value").asText());
    }

    // ---- error mapping -------------------------------------------------------------------------------------

    @Test
    void http401IsTransportErrorWithoutKey() {
        lm.allHttp(401, "text/html", HTML);
        KempApiException e = assertThrows(KempTransportException.class, () -> client.get("version"));
        assertTrue(e.getMessage().contains("401"));
        assertFalse(e.getMessage().contains(KEY));
    }

    @Test
    void http404IsTransportError() {
        lm.allHttp(404, "text/html", "<html>Not Found</html>");
        KempApiException e = assertThrows(KempTransportException.class, () -> client.get("version"));
        assertTrue(e.getMessage().contains("API"));
        assertFalse(e.getMessage().contains(KEY));
    }

    @Test
    void nonJsonIsTransportError() {
        lm.allHttp(200, "text/html", "<html>login</html>");
        assertThrows(KempTransportException.class, () -> client.get("version"));
    }

    @Test
    void permissionDeniedIsSpecificException() {
        lm.deny("listvs");
        KempApiException e = assertThrows(KempPermissionDeniedException.class, () -> client.listVirtualServices());
        assertTrue(e.getMessage().contains("listvs"));
    }

    @Test
    void otherFailureIsApiExceptionWithKempMessage() {
        lm.on("addcert", "{\"code\":422,\"message\":\"Command Failed: Invalid Format Input\",\"status\":\"fail\"}");
        KempApiException e = assertThrows(KempApiException.class, () -> client.addCertificate("x", "y", false));
        assertFalse(e instanceof KempTransportException);
        assertFalse(e instanceof KempPermissionDeniedException);
        assertTrue(e.getMessage().contains("Invalid Format Input"));
        assertTrue(e.getMessage().contains("addcert"));
    }

    @Test
    void unreachableHostIsTransportErrorWithoutKey() throws Exception {
        int port;
        try (ServerSocket s = new ServerSocket(0)) {
            port = s.getLocalPort();
        }
        try (KempClient dead = KempClient.forBaseUrl("http://127.0.0.1:" + port, KEY, 0)) {
            KempApiException e = assertThrows(KempTransportException.class, () -> dead.get("version"));
            assertFalse(e.getMessage().contains(KEY));
        }
    }

    // ---- permission probing --------------------------------------------------------------------------------

    @Test
    void probeWithAllPermissions() throws Exception {
        assertEquals(new Capabilities(true, true, true, true), client.probeCapabilities());
    }

    @Test
    void probeDetectsEachMissingPermission() throws Exception {
        lm.deny("addcert");
        assertEquals(new Capabilities(false, true, true, true), client.probeCapabilities());
        lm.server.resetAll();
        lm.defaults().deny("addintermediate");
        assertEquals(new Capabilities(true, false, true, true), client.probeCapabilities());
        lm.server.resetAll();
        lm.defaults().deny("modvs");
        assertEquals(new Capabilities(true, true, false, true), client.probeCapabilities());
        lm.server.resetAll();
        lm.defaults().denyAdminCert();
        assertEquals(new Capabilities(true, true, true, false), client.probeCapabilities());
    }

    @Test
    void probesCannotChangeAnything() throws Exception {
        client.probeCapabilities();
        JsonNode addcert = lm.requests("addcert").get(0);
        assertEquals(KempMock.PROBE, addcert.path("cert").asText());
        assertEquals("0", addcert.path("replace").asText(), "probe must never replace");
        assertFalse(KempMock.decodeData(addcert).contains("BEGIN"), "probe data must be invalid");
        JsonNode inter = lm.requests("addintermediate").get(0);
        assertEquals(KempMock.PROBE, inter.path("cert").asText());
        assertFalse(KempMock.decodeData(inter).contains("BEGIN"));
        JsonNode modvs = lm.requests("modvs").get(0);
        assertEquals(Set.of("cmd", "apikey", "vs"), fieldNames(modvs), "modvs probe must carry no change parameter");
        assertEquals("2147483646", modvs.path("vs").asText());
        JsonNode set = lm.requests("set").get(0);
        assertEquals("admincert", set.path("param").asText());
        assertEquals(KempMock.PROBE, set.path("value").asText());
        assertEquals(List.of(), lm.allWrites());
    }

    @Test
    void probeTransportErrorPropagates() {
        lm.allHttp(401, "text/html", HTML);
        assertThrows(KempTransportException.class, () -> client.probeCapabilities());
    }

    @Test
    void probeApiDisabledPropagates() {
        lm.onHttp("addcert", 404, "text/html", "<html>Not Found</html>");
        assertThrows(KempTransportException.class, () -> client.probeCapabilities());
    }

    /**
     * An empty error page (e.g. a proxy's 502/503) says nothing about permissions; reading it as "permission present"
     * would make testConnection report an unusable connector as active.
     */
    @Test
    void probeEmptyServerErrorIsNotReadAsPermissionPresent() {
        lm.allHttp(503, "text/plain", "");
        KempApiException e = assertThrows(KempApiException.class, () -> client.probeCapabilities());
        assertInstanceOf(KempTransportException.class, e);
    }

    @Test
    void emptyBodyIsTransportError() {
        lm.allHttp(200, "application/json", "");
        assertThrows(KempTransportException.class, () -> client.get("version"));
    }

    // ---- throttling ----------------------------------------------------------------------------------------

    @Test
    void throttlesConsecutiveCalls() throws Exception {
        try (KempClient slow = KempClient.forBaseUrl(lm.baseUrl(), KEY, 5.0)) {
            long start = System.nanoTime();
            for (int i = 0; i < 4; i++) {
                slow.get("version");
            }
            long elapsedMs = (System.nanoTime() - start) / 1_000_000;
            assertTrue(elapsedMs >= 500, "4 calls at 5/s took only " + elapsedMs + " ms");
        }
    }

    /**
     * Kemp drops the connection when more than 30 API calls arrive within 3 seconds. The default throttle must keep
     * that guarantee also right after a pause in the same action (a bursty limiter would release stored permits).
     */
    @Test
    void defaultRateNeverExceeds30CallsIn3SecondsEvenAfterAPause() throws Exception {
        try (KempClient real = KempClient.forBaseUrl(lm.baseUrl(), KEY, KempClient.DEFAULT_CALLS_PER_SECOND)) {
            real.get("version");
            Thread.sleep(1500); // e.g. key decryption / chain building between API calls
            for (int i = 0; i < 34; i++) {
                real.get("version");
            }
        }
        List<Long> times = lm.server.getAllServeEvents().stream().map(e -> e.getRequest().getLoggedDate().getTime())
                .sorted().toList();
        int max = 0;
        for (int i = 0; i < times.size(); i++) {
            int n = 0;
            for (int j = i; j < times.size() && times.get(j) - times.get(i) < 3000; j++) {
                n++;
            }
            max = Math.max(max, n);
        }
        assertTrue(max <= 30, max + " calls within 3 seconds");
    }

    @Test
    void zeroRateDisablesThrottling() throws Exception {
        long start = System.nanoTime();
        for (int i = 0; i < 20; i++) {
            client.get("version");
        }
        long elapsedMs = (System.nanoTime() - start) / 1_000_000;
        assertTrue(elapsedMs < 2000, "20 unthrottled calls took " + elapsedMs + " ms");
    }

    // ---- new commands --------------------------------------------------------------------------------------

    @Test
    void showVirtualServiceReturnsTopLevelObject() throws Exception {
        lm.vs(7, "192.0.2.10", 443, "tcp", "app", true, "a b");
        JsonNode vs = client.showVirtualService("7");
        assertEquals("a b", vs.path("CertFile").asText());
        assertEquals("7", lm.requests("showvs").get(0).path("vs").asText());
    }

    @Test
    void showUnknownVirtualServiceFails() {
        KempApiException e = assertThrows(KempApiException.class, () -> client.showVirtualService("99"));
        assertFalse(e instanceof KempTransportException);
    }

    @Test
    void deleteCertificateSendsDelcert() throws Exception {
        client.deleteCertificate("tlm-www.example.com");
        JsonNode del = lm.requests("delcert").get(0);
        assertEquals("tlm-www.example.com", del.path("cert").asText());
        assertEquals(KEY, del.path("apikey").asText());
    }

    @Test
    void probeAdminCertificateReadsCurrentThenSendsOneProbe() throws Exception {
        assertTrue(client.probeAdminCertificate());
        List<JsonNode> all = lm.rawBodies().stream().map(KempClientTest::json).toList();
        assertEquals(2, all.size());
        assertEquals("get", all.get(0).path("cmd").asText());
        assertEquals("admincert", all.get(0).path("param").asText());
        assertEquals("set", all.get(1).path("cmd").asText());
        assertEquals(KempMock.PROBE, all.get(1).path("value").asText());
        assertEquals(List.of(), lm.allWrites());
    }

    @Test
    void probeAdminCertificateDenied() throws Exception {
        lm.denyAdminCert();
        assertFalse(client.probeAdminCertificate());
        assertEquals(List.of(), lm.allWrites());
    }

    /** A firmware accepting the probe name would leave the web UI without a valid certificate: restore and fail. */
    @Test
    void unexpectedlySuccessfulProbeRestoresPreviousAdminCertificate() {
        lm.on("set", "value", KempMock.PROBE, KempMock.OK);
        KempApiException e = assertThrows(KempApiException.class, () -> client.probeAdminCertificate());
        assertFalse(e instanceof KempPermissionDeniedException);
        assertTrue(e.getMessage().contains("web-ui"), e.getMessage());
        List<JsonNode> restores = lm.writes("set");
        assertEquals(1, restores.size());
        assertEquals("admincert", restores.get(0).path("param").asText());
        assertEquals("web-ui", restores.get(0).path("value").asText());
        List<String> order = lm.requests("set").stream().map(n -> n.path("value").asText()).toList();
        assertEquals(List.of(KempMock.PROBE, "web-ui"), order, "restore happens after the probe");
    }

    @Test
    void unexpectedlySuccessfulProbeWithoutPreviousAdminCertificateRestoresNothing() {
        lm.get("admincert", "\"No Admin Certificate assigned\"").on("set", "value", KempMock.PROBE, KempMock.OK);
        assertThrows(KempApiException.class, () -> client.probeAdminCertificate());
        assertEquals(List.of(), lm.writes("set"));
        lm.get("admincert", "\"\"");
        assertThrows(KempApiException.class, () -> client.probeAdminCertificate());
        assertEquals(List.of(), lm.writes("set"));
    }

    @Test
    void probeCapabilitiesFailsOnUnexpectedAdminProbeSuccess() {
        lm.on("set", "value", KempMock.PROBE, KempMock.OK);
        assertThrows(KempApiException.class, () -> client.probeCapabilities());
        assertEquals("web-ui", lm.writes("set").get(0).path("value").asText());
    }

    @Test
    void probeAdminCertificateFailsWhenCurrentCannotBeRead() {
        lm.onHttp("get", 401, "text/html", HTML);
        assertThrows(KempTransportException.class, () -> client.probeAdminCertificate());
        assertEquals(List.of(), lm.requests("set"), "no probe without knowing what to restore");
    }

    // ---- list normalization --------------------------------------------------------------------------------

    @Test
    void singleObjectsAreTreatedAsOneElementLists() throws Exception {
        lm.on("listvs", "{\"code\":200,\"VS\":{\"Index\":1,\"VSAddress\":\"192.0.2.10\",\"VSPort\":\"443\","
                + "\"SSLAcceleration\":true,\"CertFile\":\"a\",\"MasterVSID\":0},\"status\":\"ok\"}");
        lm.on("showiface", "{\"code\":200,\"Interface\":{\"Id\":0,\"IPAddress\":\"192.0.2.1/24\","
                + "\"DefaultInterface\":true},\"status\":\"ok\"}");
        lm.on("listacmecert", "acmetype", "2",
                "{\"code\":200,\"Certificates\":{\"Identifier\":\"acme-cert\"},\"status\":\"ok\"}");
        lm.on("listcert", "{\"code\":200,\"cert\":{\"name\":\"only\",\"type\":\"RSA\"},\"status\":\"ok\"}");
        lm.on("listintermediate", "{\"code\":200,\"cert\":{\"name\":\"ica\",\"type\":\"RSA\"},\"status\":\"ok\"}");
        JsonNode vs = client.listVirtualServices();
        assertEquals(1, vs.size());
        assertEquals("192.0.2.10", vs.get(0).path("VSAddress").asText());
        assertEquals(List.of("192.0.2.1"), client.interfaceAddresses());
        assertEquals(Set.of("acme-cert"), client.listAcmeCertificates());
        assertEquals(List.of("only"), client.listCertificates());
        assertEquals(List.of("ica"), client.listIntermediates());
    }

    @Test
    void missingListsAreEmpty() throws Exception {
        lm.on("listvs", KempMock.OK).on("showiface", KempMock.OK).on("listcert", KempMock.OK)
                .on("listintermediate", KempMock.OK).on("listacmecert", "acmetype", "2", KempMock.OK);
        assertEquals(0, client.listVirtualServices().size());
        assertEquals(List.of(), client.interfaceAddresses());
        assertEquals(List.of(), client.listCertificates());
        assertEquals(List.of(), client.listIntermediates());
        assertEquals(Set.of(), client.listAcmeCertificates());
    }

    @Test
    void probeAdminCertificateTransportErrorPropagates() {
        lm.allHttp(401, "text/html", HTML);
        assertThrows(KempTransportException.class, () -> client.probeAdminCertificate());
    }

    @Test
    void http5xxWithJsonBodyIsTransportError() {
        lm.allHttp(500, "application/json", KempMock.INVALID);
        assertThrows(KempTransportException.class, () -> client.get("version"));
    }

    @Test
    void jsonThatIsNotAnObjectIsTransportError() {
        lm.allHttp(200, "application/json", "[\"ok\"]");
        assertThrows(KempTransportException.class, () -> client.get("version"));
        lm.allHttp(200, "application/json", "\"ok\"");
        assertThrows(KempTransportException.class, () -> client.get("version"));
    }

    @Test
    void acmePermissionDeniedPropagates() {
        lm.deny("listacmecert");
        assertThrows(KempPermissionDeniedException.class, () -> client.listAcmeCertificates());
    }

    private static JsonNode json(String body) {
        try {
            return new com.fasterxml.jackson.databind.ObjectMapper().readTree(body);
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    private static Set<String> fieldNames(JsonNode n) {
        Set<String> names = new java.util.HashSet<>();
        n.fieldNames().forEachRemaining(names::add);
        return names;
    }
}
