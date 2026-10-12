package io.github.danielstroehmann.tlm.kemp.pki;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.HexFormat;
import java.util.List;

import org.junit.jupiter.api.Test;

import io.github.danielstroehmann.tlm.kemp.testsupport.TestPki;

class PemTest {

    private static final TestPki.Ca CA = new TestPki.Ca("Pem");
    private static final KeyPair LEAF_KEYS = TestPki.rsa(2048);
    private static final X509Certificate LEAF = CA.issue(LEAF_KEYS.getPublic(), "www.example.com",
            new BigInteger("00ABCDEF0123", 16), "www.example.com");

    @Test
    void parsesSingleAndMultiplePemCertificates() throws Exception {
        assertEquals(LEAF, Pem.parseCertificate(TestPki.pem(LEAF)));
        List<X509Certificate> chain = Pem.parseCertificates(TestPki.pem(LEAF, CA.issuing, CA.root));
        assertEquals(List.of(LEAF, CA.issuing, CA.root), chain);
    }

    @Test
    void parsesBase64Der() throws Exception {
        String b64 = Base64.getMimeEncoder().encodeToString(LEAF.getEncoded());
        assertEquals(LEAF, Pem.parseCertificate(b64));
    }

    @Test
    void parsesPemWithLeadingTextAndCrLf() throws Exception {
        String text = "subject=CN = www.example.com\r\nissuer=CN = Pem Issuing CA\r\n"
                + TestPki.pem(LEAF).replace("\n", "\r\n");
        assertEquals(LEAF, Pem.parseCertificate(text));
    }

    @Test
    void blankInputGivesEmptyListButParseCertificateFails() throws Exception {
        assertTrue(Pem.parseCertificates("").isEmpty());
        assertTrue(Pem.parseCertificates(null).isEmpty());
        assertThrows(CertificateException.class, () -> Pem.parseCertificate("   "));
    }

    @Test
    void garbageIsRejected() {
        assertThrows(CertificateException.class, () -> Pem.parseCertificate("not a certificate at all"));
        assertThrows(CertificateException.class,
                () -> Pem.parseCertificate("-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n"));
    }

    @Test
    void toPemRoundTrips() throws Exception {
        String pem = Pem.toPem(LEAF);
        assertTrue(pem.startsWith("-----BEGIN CERTIFICATE-----\n"));
        assertTrue(pem.endsWith("-----END CERTIFICATE-----\n"));
        assertEquals(LEAF, Pem.parseCertificate(pem));
        String key = Pem.toPem(LEAF_KEYS.getPrivate());
        assertTrue(key.startsWith("-----BEGIN PRIVATE KEY-----\n"));
        String body = key.replaceAll("-----[A-Z ]+-----", "").replaceAll("\\s", "");
        assertEquals(Base64.getEncoder().encodeToString(LEAF_KEYS.getPrivate().getEncoded()), body);
    }

    @Test
    void thumbprintsAreUpperHexOverDer() throws Exception {
        String sha256 = HexFormat.of().withUpperCase().formatHex(MessageDigest.getInstance("SHA-256").digest(LEAF.getEncoded()));
        String sha1 = HexFormat.of().withUpperCase().formatHex(MessageDigest.getInstance("SHA-1").digest(LEAF.getEncoded()));
        assertEquals(sha256, Pem.sha256(LEAF));
        assertEquals(sha1, Pem.sha1(LEAF));
    }

    @Test
    void matchesThumbprintAcceptsSha256AndSha1InAnyNotation() throws Exception {
        String sha256 = Pem.sha256(LEAF);
        String sha1 = Pem.sha1(LEAF);
        assertTrue(Pem.matchesThumbprint(LEAF, sha256));
        assertTrue(Pem.matchesThumbprint(LEAF, sha256.toLowerCase()));
        assertTrue(Pem.matchesThumbprint(LEAF, colons(sha256)));
        assertTrue(Pem.matchesThumbprint(LEAF, " " + sha1.toLowerCase() + " "));
        assertTrue(Pem.matchesThumbprint(LEAF, colons(sha1)));
    }

    @Test
    void matchesThumbprintRejectsOtherCertificatesAndBlank() throws Exception {
        assertFalse(Pem.matchesThumbprint(LEAF, Pem.sha256(CA.issuing)));
        assertFalse(Pem.matchesThumbprint(LEAF, Pem.sha1(CA.issuing)));
        assertFalse(Pem.matchesThumbprint(LEAF, Pem.sha256(LEAF).substring(0, 63)));
        assertFalse(Pem.matchesThumbprint(LEAF, ""));
        assertFalse(Pem.matchesThumbprint(LEAF, null));
    }

    @Test
    void matchesSerialIgnoresCaseColonsAndLeadingZeros() {
        assertTrue(Pem.matchesSerial(LEAF, "ABCDEF0123"));
        assertTrue(Pem.matchesSerial(LEAF, "abcdef0123"));
        assertTrue(Pem.matchesSerial(LEAF, "00ABCDEF0123"));
        assertTrue(Pem.matchesSerial(LEAF, "AB:CD:EF:01:23"));
        assertFalse(Pem.matchesSerial(LEAF, "ABCDEF0124"));
        assertFalse(Pem.matchesSerial(LEAF, ""));
        assertFalse(Pem.matchesSerial(LEAF, null));
    }

    @Test
    void commonNameAndSelfSigned() {
        assertEquals("www.example.com", Pem.commonName(LEAF));
        assertEquals("Pem Issuing CA", Pem.commonName(CA.issuing));
        assertTrue(Pem.isSelfSigned(CA.root));
        assertFalse(Pem.isSelfSigned(CA.issuing));
        assertFalse(Pem.isSelfSigned(LEAF));
    }

    @Test
    void commonNameIsNullWithoutCn() throws Exception {
        X509Certificate noCn = selfSignedWithSubject("O=Example,C=US");
        assertNull(Pem.commonName(noCn));
    }

    @Test
    void keyMatchesOnlyTheRightKey() {
        assertTrue(Pem.keyMatches(LEAF_KEYS.getPrivate(), LEAF));
        assertFalse(Pem.keyMatches(TestPki.rsa(2048).getPrivate(), LEAF));
        assertFalse(Pem.keyMatches(TestPki.ec("secp256r1").getPrivate(), LEAF));
        KeyPair ec = TestPki.ec("secp384r1");
        X509Certificate ecLeaf = CA.issue(ec.getPublic(), "ec.example.com", BigInteger.TEN);
        assertTrue(Pem.keyMatches(ec.getPrivate(), ecLeaf));
        assertFalse(Pem.keyMatches(TestPki.ec("secp384r1").getPrivate(), ecLeaf));
    }

    @Test
    void keyMatchesBouncyCastleEcdsaKey() throws Exception {
        KeyPair ec = TestPki.ec("secp256r1");
        X509Certificate ecLeaf = CA.issue(ec.getPublic(), "ec.example.com", BigInteger.valueOf(11));
        java.security.PrivateKey bc = java.security.KeyFactory.getInstance("ECDSA", "BC")
                .generatePrivate(new java.security.spec.PKCS8EncodedKeySpec(ec.getPrivate().getEncoded()));
        assertEquals("ECDSA", bc.getAlgorithm());
        assertTrue(Pem.keyMatches(bc, ecLeaf));
        assertFalse(Pem.keyMatches(bc, LEAF));
    }

    @Test
    void isCaFromBasicConstraints() {
        assertTrue(Pem.isCa(CA.root));
        assertTrue(Pem.isCa(CA.issuing));
        assertFalse(Pem.isCa(LEAF));
    }

    @Test
    void issuedByVerifiesNameAndSignature() {
        assertTrue(Pem.issuedBy(LEAF, CA.issuing));
        assertTrue(Pem.issuedBy(CA.issuing, CA.root));
        assertFalse(Pem.issuedBy(LEAF, CA.root), "name mismatch");
        TestPki.Ca impostor = new TestPki.Ca("Pem"); // same subject names, different keys
        assertFalse(Pem.issuedBy(LEAF, impostor.issuing), "same name but not the signer");
    }

    @Test
    void dnsNamesFromSanLowerCasedOrCnFallback() {
        X509Certificate withSans = CA.issue(TestPki.rsa(2048).getPublic(), "Ignored.example.com", BigInteger.valueOf(12),
                "WWW.Example.com", "*.example.net");
        assertEquals(java.util.Set.of("www.example.com", "*.example.net"), Pem.dnsNames(withSans));
        X509Certificate cnOnly = CA.issue(TestPki.rsa(2048).getPublic(), "App.Example.com", BigInteger.valueOf(13));
        assertEquals(java.util.Set.of("app.example.com"), Pem.dnsNames(cnOnly));
    }

    @Test
    void dnsNamesEmptyWithoutSanAndCn() throws Exception {
        assertTrue(Pem.dnsNames(selfSignedWithSubject("O=Example,C=US")).isEmpty());
    }

    @Test
    void parsesDerAndConcatenatedDer() throws Exception {
        assertEquals(List.of(LEAF), Pem.parseCertificatesDer(LEAF.getEncoded()));
        byte[] a = LEAF.getEncoded();
        byte[] b = CA.issuing.getEncoded();
        byte[] both = java.util.Arrays.copyOf(a, a.length + b.length);
        System.arraycopy(b, 0, both, a.length, b.length);
        assertEquals(List.of(LEAF, CA.issuing), Pem.parseCertificatesDer(both));
        assertEquals(List.of(LEAF), Pem.parseCertificatesDer(TestPki.pem(LEAF).getBytes(java.nio.charset.StandardCharsets.US_ASCII)));
        assertThrows(CertificateException.class, () -> Pem.parseCertificatesDer(new byte[] { 0x30, 0x03, 0x01, 0x02, 0x03 }));
    }

    @Test
    void keyFamilyNormalizesBouncyCastleNames() throws Exception {
        assertEquals("RSA", Pem.keyFamily(LEAF));
        X509Certificate ecBc = CA.issue(TestPki.ec("secp384r1").getPublic(), "ec.example.com", BigInteger.valueOf(21));
        assertEquals("EC", Pem.keyFamily(ecBc));
        assertEquals("EC", Pem.keyFamily(Pem.parseCertificate(TestPki.pem(ecBc))), "JDK-parsed");
        assertEquals("RSA", Pem.keyFamily(Pem.parseCertificate(TestPki.pem(LEAF))));
    }

    private static X509Certificate selfSignedWithSubject(String dn) throws Exception {
        KeyPair kp = TestPki.rsa(2048);
        org.bouncycastle.asn1.x500.X500Name name = new org.bouncycastle.asn1.x500.X500Name(dn);
        var b = new org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder(name, BigInteger.ONE,
                new java.util.Date(System.currentTimeMillis() - 86_400_000L),
                new java.util.Date(System.currentTimeMillis() + 86_400_000L), name, kp.getPublic());
        return new org.bouncycastle.cert.jcajce.JcaX509CertificateConverter().getCertificate(
                b.build(new org.bouncycastle.operator.jcajce.JcaContentSignerBuilder("SHA256withRSA").build(kp.getPrivate())));
    }

    private static String colons(String hex) {
        return String.join(":", hex.split("(?<=\\G..)"));
    }
}
