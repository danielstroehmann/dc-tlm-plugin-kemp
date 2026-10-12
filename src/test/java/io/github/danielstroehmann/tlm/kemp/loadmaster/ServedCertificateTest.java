package io.github.danielstroehmann.tlm.kemp.loadmaster;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.Optional;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import io.github.danielstroehmann.tlm.kemp.testsupport.LocalServers;

/** Reading the certificate a TLS endpoint presents (Kemp's factory certificate is not readable via the API). */
@Timeout(30)
class ServedCertificateTest {

    @Test
    void returnsTheSelfSignedCertificatePresentedByATlsServer() throws Exception {
        try (LocalServers.Tls server = new LocalServers.Tls("Kemp Factory Example")) {
            Optional<X509Certificate> cert = ServedCertificate.fetch("127.0.0.1", server.port(), Duration.ofSeconds(5));
            assertEquals(Optional.of(server.certificate), cert);
        }
    }

    /** The certificate is captured in the trust manager, so it is returned even if the handshake then fails. */
    @Test
    void certificateIsReturnedEvenIfTheServerDemandsAClientCertificate() throws Exception {
        try (LocalServers.Tls server = new LocalServers.Tls("Kemp mTLS Example", true)) {
            assertEquals(Optional.of(server.certificate),
                    ServedCertificate.fetch("127.0.0.1", server.port(), Duration.ofSeconds(5)));
        }
    }

    @Test
    void caIssuedCertificateIsReturnedAsPresented() throws Exception {
        io.github.danielstroehmann.tlm.kemp.testsupport.TestPki.Ca ca = new io.github.danielstroehmann.tlm.kemp.testsupport.TestPki.Ca("Served");
        java.security.KeyPair keys = io.github.danielstroehmann.tlm.kemp.testsupport.TestPki.rsa(2048);
        X509Certificate leaf = ca.issue(keys.getPublic(), "vs.example.com", java.math.BigInteger.TEN, "vs.example.com");
        try (LocalServers.Tls server = new LocalServers.Tls(keys, leaf, null, false)) {
            assertEquals(Optional.of(leaf), ServedCertificate.fetch("127.0.0.1", server.port(), Duration.ofSeconds(5)),
                    "no hostname or trust check: the presented leaf is returned as is");
        }
    }

    @Test
    void repeatedFetchesWork() throws Exception {
        try (LocalServers.Tls server = new LocalServers.Tls("Kemp Factory Example")) {
            for (int i = 0; i < 3; i++) {
                assertEquals(Optional.of(server.certificate),
                        ServedCertificate.fetch("127.0.0.1", server.port(), Duration.ofSeconds(5)));
            }
        }
    }

    @Test
    void closedPortGivesEmptyQuickly() throws Exception {
        long start = System.nanoTime();
        assertEquals(Optional.empty(), ServedCertificate.fetch("127.0.0.1", LocalServers.closedPort(), Duration.ofSeconds(5)));
        assertTrue(elapsedMs(start) < 3000, "took " + elapsedMs(start) + " ms");
    }

    @Test
    void silentPlainTcpServerGivesEmptyWithinTheTimeout() throws Exception {
        try (LocalServers.Plain server = new LocalServers.Plain(null)) {
            long start = System.nanoTime();
            assertEquals(Optional.empty(), ServedCertificate.fetch("127.0.0.1", server.port(), Duration.ofMillis(800)));
            long ms = elapsedMs(start);
            assertTrue(ms < 4000, "read timeout not applied: " + ms + " ms");
        }
    }

    @Test
    void plainTextServerGivesEmpty() throws Exception {
        try (LocalServers.Plain server = new LocalServers.Plain("HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n")) {
            assertEquals(Optional.empty(), ServedCertificate.fetch("127.0.0.1", server.port(), Duration.ofSeconds(2)));
        }
    }

    private static long elapsedMs(long start) {
        return (System.nanoTime() - start) / 1_000_000;
    }
}
