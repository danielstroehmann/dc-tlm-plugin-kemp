package io.github.danielstroehmann.tlm.kemp.pki;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.StringReader;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.List;

import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.operator.DefaultAlgorithmNameFinder;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;

class CsrGeneratorTest {

    @Test
    void rsaDefaultsTo2048AndSha256WithCnAddedToSans() throws Exception {
        CsrGenerator.Result r = CsrGenerator.generate("CN=www.example.com,O=Example,C=US", "app.example.com", "RSA",
                "", "");
        PKCS10CertificationRequest csr = parse(r.csrPem());
        assertTrue(r.csrPem().startsWith("-----BEGIN CERTIFICATE REQUEST-----"));
        assertTrue(csr.isSignatureValid(new JcaContentVerifierProviderBuilder().build(csr.getSubjectPublicKeyInfo())));
        assertEquals(2048, ((RSAPublicKey) r.keyPair().getPublic()).getModulus().bitLength());
        assertEquals("SHA256WITHRSA", sigAlg(csr));
        assertEquals("www.example.com", cn(csr));
        assertEquals(List.of("www.example.com", "app.example.com"), sans(csr));
        // The CSR's public key is the generated key.
        assertTrue(java.util.Arrays.equals(r.keyPair().getPublic().getEncoded(), csr.getSubjectPublicKeyInfo().getEncoded()));
    }

    @Test
    void rsa3072WithSha384() throws Exception {
        CsrGenerator.Result r = CsrGenerator.generate("CN=www.example.com", null, "rsa", "3072", "sha384");
        assertEquals(3072, ((RSAPublicKey) r.keyPair().getPublic()).getModulus().bitLength());
        assertEquals("SHA384WITHRSA", sigAlg(parse(r.csrPem())));
    }

    @ParameterizedTest
    @CsvSource({ "EC,256,sha256,256,SHA256WITHECDSA", "ECDSA,384,sha384,384,SHA384WITHECDSA",
            "ec,P-384,SHA384withECDSA,384,SHA384WITHECDSA", "EC,521,sha512,521,SHA512WITHECDSA", "ECC,,,256,SHA256WITHECDSA" })
    void ecCurvesAndDigests(String alg, String size, String sig, int expectedBits, String expectedSig) throws Exception {
        CsrGenerator.Result r = CsrGenerator.generate("CN=ec.example.com", "", alg, size, sig);
        PKCS10CertificationRequest csr = parse(r.csrPem());
        assertEquals(expectedBits, ((ECPublicKey) r.keyPair().getPublic()).getParams().getCurve().getField().getFieldSize());
        assertEquals(expectedSig, sigAlg(csr));
        assertTrue(csr.isSignatureValid(new JcaContentVerifierProviderBuilder().build(csr.getSubjectPublicKeyInfo())));
    }

    @Test
    void nulSeparatedSubjectIsAccepted() throws Exception {
        CsrGenerator.Result r = CsrGenerator.generate("CN=www.example.com\u0000O=Example Corp\u0000C=US", "", "RSA", "2048",
                "sha256");
        X500Name subject = parse(r.csrPem()).getSubject();
        assertEquals("www.example.com", cn(parse(r.csrPem())));
        assertEquals("Example Corp", subject.getRDNs(BCStyle.O)[0].getFirst().getValue().toString());
        assertEquals("US", subject.getRDNs(BCStyle.C)[0].getFirst().getValue().toString());
    }

    @Test
    void nonDnsCnIsNotASanAndNamesAreLowerCasedAndDeduplicated() throws Exception {
        assertEquals(List.of(), CsrGenerator.subjectAlternativeNames(new X500Name("CN=Example Web Server"), ""));
        assertEquals(List.of("www.example.com", "*.example.net"),
                CsrGenerator.subjectAlternativeNames(new X500Name("CN=WWW.Example.com"),
                        " www.example.com , *.EXAMPLE.net,,WWW.EXAMPLE.COM"));
    }

    @Test
    void noSanExtensionWhenNoDnsName() throws Exception {
        CsrGenerator.Result r = CsrGenerator.generate("CN=Example Web Server,O=Example", "", "RSA", "2048", "sha256");
        assertEquals(0, parse(r.csrPem()).getAttributes(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest).length);
    }

    @ParameterizedTest
    @ValueSource(strings = { "1024", "2047", "8193", "abc", "-2048" })
    void weakOrInvalidRsaSizesAreRejected(String size) {
        assertThrows(IllegalArgumentException.class, () -> CsrGenerator.generate("CN=www.example.com", "", "RSA", size, "sha256"));
    }

    @ParameterizedTest
    @ValueSource(strings = { "192", "224", "2048", "P-192" })
    void unsupportedEcCurvesAreRejected(String size) {
        assertThrows(IllegalArgumentException.class, () -> CsrGenerator.generate("CN=www.example.com", "", "EC", size, "sha256"));
    }

    @ParameterizedTest
    @ValueSource(strings = { "DSA", "Ed25519", "RSA-PSS" })
    void unsupportedKeyAlgorithmsAreRejected(String alg) {
        assertThrows(IllegalArgumentException.class, () -> CsrGenerator.generate("CN=www.example.com", "", alg, "2048", "sha256"));
    }

    @ParameterizedTest
    @ValueSource(strings = { "sha1", "SHA1withRSA", "md5", "sha224" })
    void weakSignatureAlgorithmsAreRejected(String sig) {
        assertThrows(IllegalArgumentException.class, () -> CsrGenerator.generate("CN=www.example.com", "", "RSA", "2048", sig));
    }

    @ParameterizedTest
    @ValueSource(strings = { "", "   ", "not a distinguished name" })
    void blankOrMalformedSubjectIsRejected(String subject) {
        assertThrows(IllegalArgumentException.class, () -> CsrGenerator.generate(subject, "", "RSA", "2048", "sha256"));
    }

    @Test
    void nullSubjectIsRejected() {
        assertThrows(IllegalArgumentException.class, () -> CsrGenerator.generate(null, "", "RSA", "2048", "sha256"));
    }

    /** OWASP input validation: SAN entries must be syntactically valid DNS names (RFC 1123 / RFC 6125 wildcard). */
    @ParameterizedTest
    @ValueSource(strings = { "localhost", "exa mple.com", "a..example.com", ".example.com", "example.com.",
            "*.*.example.com", "foo.*.example.com", "*example.com", "a_b.example.com", "<script>.example.com",
            "www.example.com\nevil.example.net", "www.example.com/../x", "192.0.2.10/24", "-www.example.com",
            "www-.example.com", "www.example-.com", "192.0.2.10", "www.example.123", "*", "*.", "*.com.",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.example.com" })
    void invalidDnsNamesAreRejected(String name) {
        assertThrows(IllegalArgumentException.class,
                () -> CsrGenerator.generate("CN=www.example.com", "www.example.com," + name, "RSA", "2048", "sha256"));
    }

    @Test
    void overlongDnsNameIsRejected() {
        String label = "a".repeat(60);
        String name = String.join(".", label, label, label, label, label) + ".example.com"; // > 253 characters
        assertThrows(IllegalArgumentException.class,
                () -> CsrGenerator.subjectAlternativeNames(new X500Name("CN=x"), name));
    }

    @Test
    void boundaryValidDnsNamesAreAccepted() {
        String label63 = "a".repeat(63);
        String name253 = String.join(".", "a".repeat(63), "b".repeat(63), "c".repeat(63), "d".repeat(49), "example.com");
        assertEquals(253, name253.length());
        assertEquals(List.of(label63 + ".example.com", "x.example.com", "xn--bcher-kva.example.com", "*.example.com",
                "1.example.com", name253),
                CsrGenerator.subjectAlternativeNames(new X500Name("CN=Example"),
                        label63 + ".example.com,x.example.com,xn--bcher-kva.example.com,*.example.com,1.example.com," + name253));
        String name254 = "e" + name253;
        assertThrows(IllegalArgumentException.class, () -> CsrGenerator.subjectAlternativeNames(new X500Name("CN=x"), name254));
    }

    @Test
    void ipLiteralCnIsNotAddedAsDnsSan() {
        assertEquals(List.of(), CsrGenerator.subjectAlternativeNames(new X500Name("CN=192.0.2.10"), ""));
    }

    private static PKCS10CertificationRequest parse(String pem) throws Exception {
        try (PEMParser p = new PEMParser(new StringReader(pem))) {
            return (PKCS10CertificationRequest) p.readObject();
        }
    }

    private static String sigAlg(PKCS10CertificationRequest csr) {
        return new DefaultAlgorithmNameFinder().getAlgorithmName(csr.getSignatureAlgorithm()).toUpperCase();
    }

    private static String cn(PKCS10CertificationRequest csr) {
        return csr.getSubject().getRDNs(BCStyle.CN)[0].getFirst().getValue().toString();
    }

    private static List<String> sans(PKCS10CertificationRequest csr) {
        List<String> result = new ArrayList<>();
        var attrs = csr.getAttributes(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest);
        if (attrs.length == 0) {
            return result;
        }
        Extensions ext = Extensions.getInstance(attrs[0].getAttrValues().getObjectAt(0));
        GeneralNames names = GeneralNames.fromExtensions(ext, Extension.subjectAlternativeName);
        for (GeneralName n : names.getNames()) {
            result.add(n.getName().toString());
        }
        return result;
    }
}
