package io.github.danielstroehmann.tlm.kemp;

import static org.junit.jupiter.api.Assertions.assertTrue;

import java.math.BigInteger;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.io.TempDir;

import com.fasterxml.jackson.databind.node.ObjectNode;

import io.github.danielstroehmann.tlm.kemp.pki.FlowKeyStore;
import io.github.danielstroehmann.tlm.kemp.testsupport.KempMock;
import io.github.danielstroehmann.tlm.kemp.testsupport.LogCapture;
import io.github.danielstroehmann.tlm.kemp.testsupport.TestPki;

/** Plugin log lines and error messages are plain ASCII (TLM and sensor logs may not render other characters). */
@Timeout(60)
class AsciiOutputTest {

    @TempDir
    Path tmp;

    @Test
    void logLinesAndErrorMessagesAreAscii() throws Exception {
        List<Throwable> errors = new ArrayList<>();
        String log;
        try (KempMock lm = new KempMock().defaults(); LogCapture capture = new LogCapture()) {
            FlowKeyStore store = new FlowKeyStore(tmp.resolve("keys"));
            MockedPlugin plugin = new MockedPlugin(lm, "ascii-test-key", store);
            TestPki.Ca ca = new TestPki.Ca("Ascii");
            KeyPair keys = TestPki.rsa(2048);
            String flow = "aaaaaaaa-bbbb-cccc-dddd-000000000001";
            lm.vs(1, "192.0.2.10", 443, "tcp", "app", true, "app-cert")
                    .vs(2, "192.0.2.13", 80, "tcp", "plain", false, null)
                    .readcert("app-cert", TestPki.pem(ca.issue(TestPki.rsa(2048).getPublic(), "app.example.com", BigInteger.ONE)));

            plugin.testConnection(null);
            plugin.refreshConfiguration(null);
            plugin.generateCsr(MockedPlugin.csrRequest(flow, "CN=app.example.com", "app.example.com", "RSA", "2048"));
            store.save(flow, keys.getPrivate(), "ascii-test-key".toCharArray());
            X509Certificate leaf = ca.issue(keys.getPublic(), "app.example.com", BigInteger.TEN, "app.example.com");
            ObjectNode install = MockedPlugin.MAPPER.createObjectNode().put("flowId", flow).put("ipAddress", "192.0.2.10")
                    .put("port", "443").put("certificateChain", TestPki.pem(leaf, ca.issuing));
            plugin.installCertificate(install);

            // Refusals and failures with messages that used to contain typographic dashes.
            collect(errors, () -> plugin.installCertificate(install.deepCopy().put("ipAddress", "192.0.2.13").put("port", "80")));
            collect(errors, () -> plugin.installCertificate(install.deepCopy().put("flowId", "aaaaaaaa-bbbb-cccc-dddd-000000000002")
                    .put("certificateChain", TestPki.pem(ca.issue(TestPki.rsa(2048).getPublic(), "other.example.com",
                            BigInteger.TWO)))));
            collect(errors, () -> plugin.installCertificate(install.deepCopy().put("currentCertificateThumbprint", "AB".repeat(32))));
            collect(errors, () -> plugin.generateCsr(MockedPlugin.csrRequest("../../etc", "CN=x.example.com", "", "RSA", "2048")));
            collect(errors, () -> plugin.generateCsr(MockedPlugin.csrRequest(flow, "CN=x.example.com", "bad name", "RSA", "2048")));
            collect(errors, () -> new KempLoadMasterPlugin(MockedPlugin.config("https://x", "443", "k"), store).testConnection(null));
            collect(errors, () -> new KempLoadMasterPlugin(MockedPlugin.config("lm.example.com", "443", " "), store)
                    .testConnection(null));
            collect(errors, () -> new KempLoadMasterPlugin(MockedPlugin.config("lm.example.com", "x", "k"), store)
                    .testConnection(null));
            store.save(flow, keys.getPrivate(), "other-key".toCharArray());
            collect(errors, () -> plugin.installCertificate(install.deepCopy()
                    .put("certificateChain", TestPki.pem(ca.issue(keys.getPublic(), "app.example.com", BigInteger.valueOf(11))))));
            lm.allHttp(401, "text/html", "<html>401</html>");
            collect(errors, () -> plugin.refreshConfiguration(null));
            lm.allHttp(404, "text/html", "<html>404</html>");
            collect(errors, () -> plugin.testConnection(null));
            log = capture.text();
        }

        assertTrue(errors.size() >= 10, "expected failures did not happen: " + errors.size());
        List<String> pluginLines = log.lines().filter(l -> l.contains("io.github.danielstroehmann")).toList();
        assertTrue(pluginLines.size() >= 5, "plugin log lines not captured");
        for (String line : pluginLines) {
            assertTrue(isAscii(line), "non-ASCII plugin log line: " + escape(line));
        }
        for (Throwable t : errors) {
            for (Throwable c = t; c != null; c = c.getCause()) {
                String m = String.valueOf(c.getMessage());
                if (c.getClass().getName().startsWith("io.github.danielstroehmann")
                        || c.getClass().getName().startsWith("com.digicert")) {
                    assertTrue(isAscii(m), "non-ASCII message in " + c.getClass().getSimpleName() + ": " + escape(m));
                }
            }
        }
    }

    private static boolean isAscii(String s) {
        return s.chars().allMatch(c -> c < 0x80);
    }

    private static String escape(String s) {
        StringBuilder sb = new StringBuilder();
        s.chars().forEach(c -> sb.append(c < 0x80 ? String.valueOf((char) c) : String.format("\\u%04X", c)));
        return sb.toString();
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
