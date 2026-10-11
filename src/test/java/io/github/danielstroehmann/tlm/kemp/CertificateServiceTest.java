package io.github.danielstroehmann.tlm.kemp;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Set;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import com.fasterxml.jackson.databind.JsonNode;

import io.github.danielstroehmann.tlm.kemp.client.Capabilities;
import io.github.danielstroehmann.tlm.kemp.client.KempClient;
import io.github.danielstroehmann.tlm.kemp.loadmaster.Snapshot;
import io.github.danielstroehmann.tlm.kemp.loadmaster.Target;
import io.github.danielstroehmann.tlm.kemp.loadmaster.VirtualService;
import io.github.danielstroehmann.tlm.kemp.pki.Pem;
import io.github.danielstroehmann.tlm.kemp.testsupport.KempMock;
import io.github.danielstroehmann.tlm.kemp.testsupport.TestPki;

/** Component: CertificateService with a real KempClient against the mock LoadMaster. */
@org.junit.jupiter.api.Timeout(30)
class CertificateServiceTest {

    private static final TestPki.Ca CA = new TestPki.Ca("Service");
    private static final Capabilities ALL = new Capabilities(true, true, true, true);

    private KempMock lm;
    private KempClient client;
    private CertificateService service;

    @BeforeEach
    void start() {
        lm = new KempMock().defaults();
        client = KempClient.forBaseUrl(lm.baseUrl(), "service-key", 0);
        service = new CertificateService(client);
    }

    @AfterEach
    void stop() {
        client.close();
        lm.close();
    }

    private static X509Certificate withSubject(String dn) throws Exception {
        KeyPair kp = TestPki.rsa(2048);
        X500Name name = new X500Name(dn);
        var b = new JcaX509v3CertificateBuilder(name, BigInteger.ONE, new java.util.Date(), new java.util.Date(
                System.currentTimeMillis() + 86_400_000L), name, kp.getPublic());
        return new JcaX509CertificateConverter()
                .getCertificate(b.build(new JcaContentSignerBuilder("SHA256withRSA").build(kp.getPrivate())));
    }

    @Test
    void identifierFromCommonName() throws Exception {
        assertEquals("tlm-www.example.com", service.newIdentifier(withSubject("CN=www.example.com")));
        assertEquals("tlm-wildcard.example.net", service.newIdentifier(withSubject("CN=*.example.net")));
        assertEquals("tlm-My-Web-Server--1-", service.newIdentifier(withSubject("CN=My Web Server (1)")));
        assertEquals("tlm-certificate", service.newIdentifier(withSubject("O=Example,C=US")));
    }

    @Test
    void identifierForMaximumLengthCommonNameIsComplete() throws Exception {
        // RFC 5280 limits the CN to 64 characters (enforced by BouncyCastle), so the identifier stays well below 200.
        String cn = "a".repeat(52) + ".example.com";
        assertEquals(64, cn.length());
        assertEquals("tlm-" + cn, service.newIdentifier(withSubject("CN=" + cn)));
    }

    @Test
    void identifierCollisionIsCaseInsensitive() throws Exception {
        lm.certificates("TLM-WWW.EXAMPLE.COM");
        String id = service.newIdentifier(withSubject("CN=www.example.com"));
        assertTrue(id.matches("tlm-www\\.example\\.com-\\d{14}"), id);
    }

    @Test
    void identifierCannotInjectIntoSpaceSeparatedCertFile() throws Exception {
        String id = service.newIdentifier(withSubject("CN=evil.example.com other-cert"));
        assertTrue(id.matches("[A-Za-z0-9._-]+"), id);
    }

    /**
     * Renewal on an SNI service: one of the other certificates on the service cannot be read/parsed. The matching
     * certificate must still be found and replaced instead of aborting (findBound tolerates this, install should too).
     */
    @Test
    void renewalToleratesUnparseableSiblingCertificate() throws Exception {
        KeyPair oldKeys = TestPki.rsa(2048);
        X509Certificate old = CA.issue(oldKeys.getPublic(), "shop.example.com", BigInteger.valueOf(5));
        KeyPair newKeys = TestPki.rsa(2048);
        X509Certificate renewed = CA.issue(newKeys.getPublic(), "shop.example.com", BigInteger.valueOf(6));
        lm.readcert("broken", "not a certificate").readcert("shop", TestPki.pem(old));

        VirtualService vs = new VirtualService("2", "192.0.2.11", 443, "tcp", "sni", true, List.of("broken", "shop"), false,
                false);
        Snapshot snapshot = new Snapshot(List.of(vs), Set.of(), List.of(KempMock.MGMT_IP), 8443, "web-ui", KempMock.MGMT_IP);
        service.install(snapshot, ALL, new Target.Vs(vs), newKeys.getPrivate(),
                CertificateService.buildChain(List.of(renewed), newKeys.getPrivate()), Pem.sha256(old));

        List<JsonNode> adds = lm.writes("addcert");
        assertEquals(1, adds.size());
        assertEquals("shop", adds.get(0).path("cert").asText());
        assertEquals("1", adds.get(0).path("replace").asText());
    }

    // ---- buildChain ----------------------------------------------------------------------------------------

    @Test
    void buildChainPicksLeafByKeyAndOrdersPathWithoutRoot() throws Exception {
        KeyPair keys = TestPki.rsa(2048);
        TestPki.Issuer sub = CA.subordinate("Service Sub CA");
        X509Certificate leaf = sub.issue(keys.getPublic(), "www.example.com", BigInteger.valueOf(7));
        CertificateService.Chain chain = CertificateService.buildChain(
                List.of(CA.root, CA.issuing, leaf, sub.cert()), keys.getPrivate());
        assertEquals(leaf, chain.leaf());
        assertEquals(List.of(sub.cert(), CA.issuing), chain.intermediates());
    }

    @Test
    void buildChainRemovesDuplicatesAndForeignCertificates() throws Exception {
        KeyPair keys = TestPki.rsa(2048);
        X509Certificate leaf = CA.issue(keys.getPublic(), "www.example.com", BigInteger.valueOf(8));
        X509Certificate otherLeaf = CA.issue(TestPki.rsa(2048).getPublic(), "other.example.com", BigInteger.valueOf(9));
        TestPki.Ca rogue = new TestPki.Ca("Service"); // same names, other keys
        CertificateService.Chain chain = CertificateService.buildChain(List.of(otherLeaf, leaf, CA.issuing, leaf,
                rogue.issuing, CA.issuing, rogue.root, CA.root), keys.getPrivate());
        assertEquals(leaf, chain.leaf());
        assertEquals(List.of(CA.issuing), chain.intermediates());
    }

    @Test
    void buildChainIgnoresNonCaIssuerCandidates() throws Exception {
        // A non-CA certificate whose subject equals the leaf's issuer and that even shares the issuing key is no CA.
        KeyPair keys = TestPki.rsa(2048);
        X509Certificate leaf = CA.issue(keys.getPublic(), "www.example.com", BigInteger.valueOf(10));
        X509Certificate fakeIssuer = CA.issue(CA.issuingKeys.getPublic(), "Service Issuing CA", BigInteger.valueOf(11));
        assertEquals(List.of(), CertificateService.buildChain(List.of(leaf, fakeIssuer), keys.getPrivate()).intermediates());
    }

    @Test
    void buildChainEcKeyFromBouncyCastle() throws Exception {
        KeyPair ec = TestPki.ec("secp384r1");
        X509Certificate leaf = CA.issue(ec.getPublic(), "ec.example.com", BigInteger.valueOf(12));
        java.security.PrivateKey bcKey = java.security.KeyFactory.getInstance("ECDSA", "BC")
                .generatePrivate(new java.security.spec.PKCS8EncodedKeySpec(ec.getPrivate().getEncoded()));
        assertEquals("ECDSA", bcKey.getAlgorithm());
        assertEquals(leaf, CertificateService.buildChain(List.of(CA.issuing, leaf), bcKey).leaf());
    }

    @Test
    void buildChainWithoutMatchingCertificateFails() {
        KeyPair keys = TestPki.rsa(2048);
        X509Certificate foreign = CA.issue(TestPki.rsa(2048).getPublic(), "www.example.com", BigInteger.valueOf(13));
        assertThrows(com.digicert.tlm.workflows.WorkflowExecutionException.class,
                () -> CertificateService.buildChain(List.of(foreign, CA.issuing), keys.getPrivate()));
        assertThrows(com.digicert.tlm.workflows.WorkflowExecutionException.class,
                () -> CertificateService.buildChain(List.of(), keys.getPrivate()));
    }

    // ---- covers (H1) ---------------------------------------------------------------------------------------

    private static Set<String> names(String... n) {
        return Set.of(n);
    }

    @Test
    void coversRequiresEveryOldName() {
        assertTrue(CertificateService.covers(names("a.example.com", "shared.example.com"), names("a.example.com")));
        assertTrue(CertificateService.covers(names("a.example.com", "shared.example.com"),
                names("shared.example.com", "a.example.com")));
        assertFalse(CertificateService.covers(names("shared.example.com"), names("a.example.com", "shared.example.com")),
                "partial overlap is not coverage");
        assertFalse(CertificateService.covers(names("b.example.com"), names("a.example.com")));
    }

    @Test
    void coversWithSingleLabelWildcard() {
        assertTrue(CertificateService.covers(names("*.example.com"), names("www.example.com", "api.example.com")));
        assertFalse(CertificateService.covers(names("*.example.com"), names("a.b.example.com")), "wildcard is one label");
        assertFalse(CertificateService.covers(names("*.example.com"), names("example.com")), "apex is not covered");
        assertFalse(CertificateService.covers(names("www.example.com"), names("*.example.com")),
                "a specific name never covers a wildcard");
        assertTrue(CertificateService.covers(names("*.example.com"), names("*.example.com")));
        assertFalse(CertificateService.covers(names("*.example.net"), names("www.example.com")));
        assertFalse(CertificateService.covers(names("*.example.com"), names("wwwexample.com")));
    }

    @Test
    void coversNothingWhenOldHasNoNames() {
        assertFalse(CertificateService.covers(names("www.example.com"), Set.of()));
        assertFalse(CertificateService.covers(Set.of(), names("www.example.com")));
    }

    // ---- validateLeaf --------------------------------------------------------------------------------------

    private static final java.time.Instant NOW = java.time.Instant.now();
    private static final java.time.Duration DAY = java.time.Duration.ofDays(1);

    @Test
    void validLeafVariantsAreAccepted() throws Exception {
        var pub = TestPki.rsa(2048).getPublic();
        CertificateService.validateLeaf(CA.issueCustom(pub, "a.example.com", NOW.minus(DAY), NOW.plus(DAY), false));
        CertificateService.validateLeaf(CA.issueCustom(pub, "a.example.com", NOW.minus(DAY), NOW.plus(DAY), false,
                org.bouncycastle.asn1.x509.KeyPurposeId.id_kp_serverAuth, org.bouncycastle.asn1.x509.KeyPurposeId.id_kp_clientAuth));
        CertificateService.validateLeaf(CA.issueCustom(pub, "a.example.com", NOW.minus(DAY), NOW.plus(DAY), false,
                org.bouncycastle.asn1.x509.KeyPurposeId.anyExtendedKeyUsage));
    }

    @Test
    void unusableLeavesAreRejected() {
        var pub = TestPki.rsa(2048).getPublic();
        for (X509Certificate bad : List.of(
                CA.issueCustom(pub, "ca.example.com", NOW.minus(DAY), NOW.plus(DAY), true),
                CA.issueCustom(pub, "old.example.com", NOW.minus(DAY.multipliedBy(10)), NOW.minus(DAY), false),
                CA.issueCustom(pub, "future.example.com", NOW.plus(DAY), NOW.plus(DAY.multipliedBy(10)), false),
                CA.issueCustom(pub, "client.example.com", NOW.minus(DAY), NOW.plus(DAY), false,
                        org.bouncycastle.asn1.x509.KeyPurposeId.id_kp_clientAuth),
                CA.issueCustom(pub, "code.example.com", NOW.minus(DAY), NOW.plus(DAY), false,
                        org.bouncycastle.asn1.x509.KeyPurposeId.id_kp_codeSigning,
                        org.bouncycastle.asn1.x509.KeyPurposeId.id_kp_emailProtection))) {
            assertThrows(com.digicert.tlm.workflows.WorkflowExecutionException.class,
                    () -> CertificateService.validateLeaf(bad), Pem.commonName(bad));
        }
    }

    @Test
    void buildChainRejectsExpiredLeafMatchingTheKey() {
        KeyPair keys = TestPki.rsa(2048);
        X509Certificate expired = CA.issueCustom(keys.getPublic(), "old.example.com", NOW.minus(DAY.multipliedBy(10)),
                NOW.minus(DAY), false);
        var e = assertThrows(com.digicert.tlm.workflows.WorkflowExecutionException.class,
                () -> CertificateService.buildChain(List.of(expired, CA.issuing), keys.getPrivate()));
        assertTrue(e.getMessage().contains("not currently valid"), e.getMessage());
    }

    @Test
    void alreadyInstalledWithKeyOnlyCountsTheCertificateForThatKey() throws Exception {
        KeyPair flowKeys = TestPki.rsa(2048);
        X509Certificate bound = CA.issue(TestPki.rsa(2048).getPublic(), "www.example.com", BigInteger.valueOf(16));
        X509Certificate issued = CA.issue(flowKeys.getPublic(), "www.example.com", BigInteger.valueOf(17));
        lm.readcert("bound", TestPki.pem(bound));
        VirtualService vs = new VirtualService("1", "192.0.2.10", 443, "tcp", "app", true, List.of("bound"), false, false);
        Snapshot snapshot = new Snapshot(List.of(vs), Set.of(), List.of(KempMock.MGMT_IP), 8443, null, KempMock.MGMT_IP);
        var key = java.util.Optional.of(flowKeys.getPrivate());
        // The package contains the currently bound certificate, but not as the certificate issued for this flow.
        assertFalse(service.alreadyInstalled(snapshot, ALL, new Target.Vs(vs), List.of(bound, issued), key));
        assertFalse(service.alreadyInstalled(snapshot, ALL, new Target.Vs(vs), List.of(bound), key));
        assertTrue(service.alreadyInstalled(snapshot, ALL, new Target.Vs(vs), List.of(bound), java.util.Optional.empty()));
        lm.readcert("bound", TestPki.pem(issued));
        assertTrue(new CertificateService(client).alreadyInstalled(snapshot, ALL, new Target.Vs(vs), List.of(bound, issued), key));
    }

    // ---- alreadyInstalled ----------------------------------------------------------------------------------

    @Test
    void alreadyInstalledOnlyForBoundNonCaCertificate() throws Exception {
        X509Certificate leaf = CA.issue(TestPki.rsa(2048).getPublic(), "www.example.com", BigInteger.valueOf(14));
        lm.readcert("bound", TestPki.pem(leaf));
        VirtualService vs = new VirtualService("1", "192.0.2.10", 443, "tcp", "app", true, List.of("missing", "bound"),
                false, false);
        Snapshot snapshot = new Snapshot(List.of(vs), Set.of(), List.of(KempMock.MGMT_IP), 8443, null, KempMock.MGMT_IP);
        assertTrue(service.alreadyInstalled(snapshot, ALL, new Target.Vs(vs), List.of(CA.issuing, leaf),
                java.util.Optional.empty()));
        X509Certificate other = CA.issue(TestPki.rsa(2048).getPublic(), "www.example.com", BigInteger.valueOf(15));
        assertFalse(new CertificateService(client).alreadyInstalled(snapshot, ALL, new Target.Vs(vs), List.of(other),
                java.util.Optional.empty()));
        assertEquals(List.of(), lm.allWrites());
    }

    @Test
    void alreadyInstalledTransportErrorPropagates() {
        lm.onHttp("readcert", 503, "text/html", "<html>503</html>");
        VirtualService vs = new VirtualService("1", "192.0.2.10", 443, "tcp", "app", true, List.of("bound"), false, false);
        Snapshot snapshot = new Snapshot(List.of(vs), Set.of(), List.of(KempMock.MGMT_IP), 8443, null, KempMock.MGMT_IP);
        assertThrows(io.github.danielstroehmann.tlm.kemp.client.KempApiException.class,
                () -> service.alreadyInstalled(snapshot, ALL, new Target.Vs(vs), List.of(CA.issuing, CA.issue(
                        TestPki.rsa(2048).getPublic(), "x.example.com", BigInteger.valueOf(77))), java.util.Optional.empty()));
    }

    @Test
    void findBoundForManagementWithoutAdminCertIsEmpty() throws Exception {
        Snapshot snapshot = new Snapshot(List.of(), Set.of(), List.of(KempMock.MGMT_IP), 8443, null, KempMock.MGMT_IP);
        assertTrue(service.findBound(snapshot, new Target.Management(), "01").isEmpty());
        assertEquals(List.of(), lm.requests("readcert"));
    }
}
