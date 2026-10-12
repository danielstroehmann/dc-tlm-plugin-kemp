package io.github.danielstroehmann.tlm.kemp;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.math.BigInteger;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import com.fasterxml.jackson.databind.node.ObjectNode;

import io.github.danielstroehmann.tlm.kemp.pki.FlowKeyStore;
import io.github.danielstroehmann.tlm.kemp.testsupport.KempMock;
import io.github.danielstroehmann.tlm.kemp.testsupport.LogCapture;
import io.github.danielstroehmann.tlm.kemp.testsupport.TestPki;

/** OWASP (sensitive data exposure): the API key and private keys never appear in logs or exception messages. */
@org.junit.jupiter.api.Timeout(60)
class SecretLeakTest {

    private static final String KEY = "Qw7-LEAKCHECK-APIKEY-9f3e2d1c";

    @TempDir
    Path tmp;

    @Test
    void apiKeyAndPrivateKeyNeverLoggedOrInExceptions() throws Exception {
        List<Throwable> errors = new ArrayList<>();
        String log;
        String privateKeyB64;
        try (LogCapture capture = new LogCapture(); KempMock lm = new KempMock().defaults()) {
            FlowKeyStore store = new FlowKeyStore(tmp.resolve("keys"));
            MockedPlugin plugin = new MockedPlugin(lm, KEY, store);
            TestPki.Ca ca = new TestPki.Ca("Leak");
            KeyPair keys = TestPki.rsa(2048);
            privateKeyB64 = Base64.getEncoder().encodeToString(keys.getPrivate().getEncoded()).substring(100, 160);
            String flow = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";
            lm.vs(1, "192.0.2.10", 443, "tcp", "app", true, "app-cert")
                    .readcert("app-cert", TestPki.pem(ca.issue(TestPki.rsa(2048).getPublic(), "app.example.com", BigInteger.ONE)));

            // Successful paths (LogCapture raises the plugin log level to TRACE).
            plugin.testConnection(null);
            plugin.refreshConfiguration(null);
            plugin.generateCsr(MockedPlugin.csrRequest(flow, "CN=app.example.com", "app.example.com", "RSA", "2048"));
            store.save(flow, keys.getPrivate(), KEY.toCharArray());
            X509Certificate leaf = ca.issue(keys.getPublic(), "app.example.com", BigInteger.TEN);
            ObjectNode install = MockedPlugin.MAPPER.createObjectNode().put("flowId", flow).put("ipAddress", "192.0.2.10")
                    .put("port", "443").put("certificateChain", TestPki.pem(leaf, ca.issuing));
            plugin.installCertificate(install);

            // Failure paths.
            store.save(flow, keys.getPrivate(), KEY.toCharArray());
            lm.on("addcert", KempMock.INVALID).on("addcert", "cert", KempMock.PROBE, KempMock.INVALID);
            collect(errors, () -> plugin.installCertificate(install));
            collect(errors, () -> plugin.installCertificate(install.deepCopy().put("ipAddress", "203.0.113.1")));
            collect(errors, () -> plugin.generateCsr(MockedPlugin.csrRequest("../../etc", "CN=x.example.com", "", "RSA", "2048")));
            lm.deny("addintermediate");
            collect(errors, () -> plugin.testConnection(null));
            lm.allHttp(401, "text/html", "<html>401 " + "Unauthorized</html>");
            collect(errors, () -> plugin.testConnection(null));
            collect(errors, () -> plugin.refreshConfiguration(null));
            collect(errors, () -> plugin.validateCertificate(install));
            lm.allHttp(200, "text/html", "<html>login</html>");
            collect(errors, () -> plugin.refreshConfiguration(null));
            lm.server.stop();
            collect(errors, () -> plugin.testConnection(null));
            log = capture.text();
        }

        assertTrue(errors.size() >= 8, "failure paths did not fail: " + errors.size());
        assertTrue(log.contains("installCertificate"), "log capture did not see plugin output");
        assertFalse(log.contains(KEY), "API key found in log output");
        assertFalse(log.contains(privateKeyB64), "private key material found in log output");
        assertFalse(log.contains("BEGIN PRIVATE KEY"), "private key PEM found in log output");
        for (Throwable t : errors) {
            for (Throwable c = t; c != null; c = c.getCause()) {
                assertFalse(String.valueOf(c.getMessage()).contains(KEY), "API key in exception message: " + c);
                assertFalse(String.valueOf(c).contains(KEY), "API key in exception: " + c);
            }
        }
    }

    /**
     * openClient's DEBUG line describes the key as delivered (length, Base64 flag, invisible characters) and as used
     * (length, SHA-256 prefix) - but neither the plain key nor its Base64 form may appear in logs or exceptions.
     */
    @Test
    void connectDebugLogDescribesKeyWithoutRevealingIt() throws Exception {
        String encoded = Base64.getEncoder().encodeToString(KEY.getBytes(java.nio.charset.StandardCharsets.UTF_8));
        String configured = " " + encoded + "\n";
        byte[] digest = java.security.MessageDigest.getInstance("SHA-256").digest(KEY.getBytes(java.nio.charset.StandardCharsets.UTF_8));
        String prefix = java.util.HexFormat.of().formatHex(digest, 0, 4);
        List<Throwable> errors = new ArrayList<>();
        String log;
        try (KempMock lm = new KempMock(true).defaults().requireApiKey(KEY); LogCapture capture = new LogCapture()) {
            KempConfiguration config = MockedPlugin.config("127.0.0.1", String.valueOf(lm.server.httpsPort()), configured);
            KempLoadMasterPlugin plugin = new KempLoadMasterPlugin(config, new FlowKeyStore(tmp));
            plugin.testConnection(null);
            lm.allHttp(401, "text/html", "<html>401</html>");
            collect(errors, () -> plugin.refreshConfiguration(null));
            collect(errors, () -> plugin.testConnection(null));
            log = capture.text();
        }
        String line = log.lines().filter(l -> l.contains("Connecting to LoadMaster")).findFirst()
                .orElseThrow(() -> new AssertionError("no connect debug line in: " + log));
        assertTrue(line.contains("127.0.0.1:"), line);
        assertTrue(line.contains("as delivered: length " + configured.length()), line);
        assertTrue(line.contains("Base64-encoded true"), line);
        assertTrue(line.contains("non-printable characters [U+0020 at 0, U+000A at " + (configured.length() - 1) + "]"), line);
        assertTrue(line.contains("as used: length " + KEY.length()), line);
        assertTrue(line.contains("sha256 prefix " + prefix), line);
        assertTrue(line.contains("unmapped settings: []"), line);
        assertTrue(errors.size() >= 2, "failure paths did not fail");
        for (String secret : List.of(KEY, encoded, KEY.substring(0, KEY.length() / 2), encoded.substring(0, 20))) {
            assertFalse(log.contains(secret), "key material found in log output: " + secret.length() + " chars");
            for (Throwable t : errors) {
                for (Throwable c = t; c != null; c = c.getCause()) {
                    assertFalse(String.valueOf(c).contains(secret), "key material in exception: " + c);
                }
            }
        }
    }

    @Test
    void connectDebugLogForPlainKey() throws Exception {
        String log;
        try (KempMock lm = new KempMock(true).defaults().requireApiKey(KEY); LogCapture capture = new LogCapture()) {
            new KempLoadMasterPlugin(MockedPlugin.config("127.0.0.1", String.valueOf(lm.server.httpsPort()), KEY),
                    new FlowKeyStore(tmp)).testConnection(null);
            log = capture.text();
        }
        String line = log.lines().filter(l -> l.contains("Connecting to LoadMaster")).findFirst().orElseThrow();
        assertTrue(line.contains("Base64-encoded false"), line);
        assertTrue(line.contains("non-printable characters none"), line);
        assertTrue(line.contains("as delivered: length " + KEY.length()) && line.contains("as used: length " + KEY.length()), line);
        assertFalse(log.contains(KEY));
    }

    @Test
    void configurationToStringHidesApiKey() {
        assertFalse(MockedPlugin.config("lm.example.com", "443", KEY).toString().contains(KEY));
    }

    private interface Action {
        void run() throws Exception;
    }

    private static void collect(List<Throwable> errors, Action action) {
        try {
            action.run();
        } catch (Throwable t) {
            errors.add(t);
        }
    }
}
