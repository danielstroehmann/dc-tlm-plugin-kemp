package io.github.danielstroehmann.tlm.kemp.pki;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.net.ServerSocket;
import java.nio.charset.StandardCharsets;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import io.github.danielstroehmann.tlm.kemp.testsupport.KempMock;
import io.github.danielstroehmann.tlm.kemp.testsupport.TestPki;

/** Unpacking and downloading TLM certificate packages (OWASP: untrusted input, SSRF/TLS, resource exhaustion). */
@Timeout(30)
class CertificatePackageTest {

    private static final TestPki.Ca CA = new TestPki.Ca("Package");
    private static final X509Certificate LEAF = CA.issue(TestPki.rsa(2048).getPublic(), "www.example.com",
            BigInteger.valueOf(42), "www.example.com");

    private static byte[] ascii(String s) {
        return s.getBytes(StandardCharsets.US_ASCII);
    }

    private static byte[] pkcs7(X509Certificate... certs) throws Exception {
        return CertificateFactory.getInstance("X.509").generateCertPath(List.of(certs)).getEncoded("PKCS7");
    }

    private static byte[] zip(Map<String, byte[]> entries) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        try (ZipOutputStream z = new ZipOutputStream(out)) {
            for (var e : entries.entrySet()) {
                z.putNextEntry(new ZipEntry(e.getKey()));
                if (e.getValue() != null) {
                    z.write(e.getValue());
                }
                z.closeEntry();
            }
        }
        return out.toByteArray();
    }

    // ---- single files --------------------------------------------------------------------------------------

    @Test
    void parsesPemChain() throws Exception {
        assertEquals(List.of(LEAF, CA.issuing, CA.root), CertificatePackage.parse(ascii(TestPki.pem(LEAF, CA.issuing, CA.root))));
    }

    @Test
    void parsesDer() throws Exception {
        assertEquals(List.of(LEAF), CertificatePackage.parse(LEAF.getEncoded()));
    }

    @Test
    void parsesPkcs7Der() throws Exception {
        assertEquals(java.util.Set.of(LEAF, CA.issuing), java.util.Set.copyOf(CertificatePackage.parse(pkcs7(LEAF, CA.issuing))));
    }

    @Test
    void parsesPkcs7Pem() throws Exception {
        String pem = "-----BEGIN PKCS7-----\n" + Base64.getMimeEncoder(64, "\n".getBytes()).encodeToString(pkcs7(LEAF, CA.issuing))
                + "\n-----END PKCS7-----\n";
        assertEquals(java.util.Set.of(LEAF, CA.issuing), java.util.Set.copyOf(CertificatePackage.parse(ascii(pem))));
    }

    @Test
    void garbageIsRejected() {
        assertThrows(CertificateException.class, () -> CertificatePackage.parse(ascii("this is not a certificate")));
    }

    // ---- ZIP -----------------------------------------------------------------------------------------------

    @Test
    void zipWithMixedEntriesKeepsOnlyCertificateFiles() throws Exception {
        Map<String, byte[]> entries = new java.util.LinkedHashMap<>();
        entries.put("certs/", null);
        entries.put("certs/www_example_com.CRT", ascii(TestPki.pem(LEAF)));
        entries.put("certs/Issuing.Cer", CA.issuing.getEncoded());
        entries.put("certs/chain.p7b", pkcs7(CA.issuing, CA.root));
        entries.put("certs/root.PEM", ascii(TestPki.pem(CA.root)));
        entries.put("certs/README.txt", ascii("not a certificate"));
        entries.put("certs/private.key", ascii("garbage that must not be parsed"));
        entries.put("certs/cert.pem.exe", ascii("garbage"));
        List<X509Certificate> certs = CertificatePackage.parse(zip(entries));
        assertEquals(java.util.Set.of(LEAF, CA.issuing, CA.root), java.util.Set.copyOf(certs));
        assertEquals(5, certs.size(), "duplicates are left to buildChain");
    }

    @Test
    void emptyZipGivesNoCertificates() throws Exception {
        assertEquals(List.of(), CertificatePackage.parse(zip(Map.of("readme.txt", ascii("x")))));
    }

    @Test
    void zipEntryNamesAreNeverUsedAsPaths() throws Exception {
        // Traversal names are only used for the extension check; nothing is written to disk.
        assertEquals(List.of(LEAF), CertificatePackage.parse(zip(Map.of("../../../../tmp/evil.pem", ascii(TestPki.pem(LEAF))))));
    }

    @Test
    void garbageCertificateEntryIsRejected() {
        assertThrows(CertificateException.class,
                () -> CertificatePackage.parse(zip(Map.of("cert.pem", ascii("-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n")))));
    }

    @Test
    void tooManyEntriesAreRejected() throws Exception {
        Map<String, byte[]> entries = new java.util.LinkedHashMap<>();
        for (int i = 0; i < CertificatePackage.MAX_ENTRIES + 1; i++) {
            entries.put("file" + i + ".txt", ascii("x"));
        }
        assertThrows(IOException.class, () -> CertificatePackage.parse(zip(entries)));
        entries.remove("file0.txt");
        CertificatePackage.parse(zip(entries)); // exactly at the limit is fine
    }

    @Test
    void oversizedEntryIsRejectedEvenIfHighlyCompressed() throws Exception {
        byte[] bomb = new byte[CertificatePackage.MAX_ENTRY_BYTES + 1];
        Arrays.fill(bomb, (byte) 'A');
        byte[] archive = zip(Map.of("bomb.pem", bomb));
        assertTrue(archive.length < 64 * 1024, "test archive should be small: " + archive.length);
        IOException e = assertThrows(IOException.class, () -> CertificatePackage.parse(archive));
        assertTrue(e.getMessage().contains("exceeds"), e.getMessage());
    }

    @Test
    void oversizedIgnoredEntryIsNotRead() throws Exception {
        byte[] big = new byte[CertificatePackage.MAX_ENTRY_BYTES + 1];
        assertEquals(List.of(LEAF), CertificatePackage.parse(zip(Map.of("big.bin", big, "leaf.crt", LEAF.getEncoded()))));
    }

    // ---- download ------------------------------------------------------------------------------------------

    @ParameterizedTest
    @ValueSource(strings = { "http://127.0.0.1:%d/package.zip", "HTTP://127.0.0.1:%d/package.zip", "ftp://127.0.0.1:%d/x",
            "file:///etc/hosts", "jar:file:/x.jar!/y" })
    void nonHttpsLinksAreRejectedBeforeAnyRequest(String template) throws Exception {
        try (KempMock server = new KempMock()) {
            String link = template.contains("%d") ? String.format(template, server.server.port()) : template;
            assertThrows(IOException.class, () -> CertificatePackage.download(link));
            assertEquals(0, server.server.getAllServeEvents().size());
        }
    }

    /** TLS must be verified against the JVM trust store: a self-signed server certificate is refused. */
    @Test
    void untrustedHttpsServerIsRefused() throws Exception {
        try (KempMock server = new KempMock(true)) {
            server.server.stubFor(com.github.tomakehurst.wiremock.client.WireMock.get("/package.pem")
                    .willReturn(com.github.tomakehurst.wiremock.client.WireMock.aResponse().withBody(TestPki.pem(LEAF))));
            assertThrows(IOException.class, () -> CertificatePackage.download(server.httpsUrl() + "/package.pem"));
            assertEquals(0, server.server.getAllServeEvents().size(), "no request may be served without trusted TLS");
        }
    }

    @Test
    void unreachableHttpsServerFails() throws Exception {
        int port;
        try (ServerSocket s = new ServerSocket(0)) {
            port = s.getLocalPort();
        }
        int closed = port;
        assertThrows(IOException.class, () -> CertificatePackage.download("https://127.0.0.1:" + closed + "/package.zip"));
    }
}
