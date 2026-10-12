package io.github.danielstroehmann.tlm.kemp;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.math.BigInteger;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import com.digicert.tlm.workflows.automation.dto.RefreshConfigurationResponse;
import com.digicert.tlm.workflows.automation.dto.RefreshConfigurationResponse.Certificate;
import com.digicert.tlm.workflows.automation.dto.RefreshConfigurationResponse.DataIpInfo;
import com.fasterxml.jackson.databind.JsonNode;

import io.github.danielstroehmann.tlm.kemp.client.KempClient;
import io.github.danielstroehmann.tlm.kemp.loadmaster.Snapshot;
import io.github.danielstroehmann.tlm.kemp.pki.Pem;
import io.github.danielstroehmann.tlm.kemp.testsupport.KempMock;
import io.github.danielstroehmann.tlm.kemp.testsupport.LocalServers;
import io.github.danielstroehmann.tlm.kemp.testsupport.TestPki;

/** Component: Inventory with the presented-certificate lookup for Kemp's factory certificate overridden. */
@Timeout(30)
class InventoryTest {

    private static final String FACTORY = "0123456789abcdef0123456789abcdef";
    private static final TestPki.Ca CA = new TestPki.Ca("InventoryComponent");
    private static final X509Certificate FACTORY_CERT = TestPki.selfSigned(TestPki.rsa(2048), "Kemp Factory Example");
    private static final X509Certificate APP = CA.issue(TestPki.rsa(2048).getPublic(), "app.example.com", BigInteger.ONE);

    private KempMock lm;
    private KempClient client;
    private final List<String> lookups = new ArrayList<>();

    @BeforeEach
    void start() {
        lm = new KempMock().defaults();
        client = KempClient.forBaseUrl(lm.baseUrl(), "inventory-key", 0);
    }

    @AfterEach
    void stop() {
        client.close();
        lm.close();
    }

    private RefreshConfigurationResponse<JsonNode> build(Optional<X509Certificate> presented) throws Exception {
        Inventory inventory = new Inventory(client);
        inventory.servedCertificate = (host, port) -> {
            lookups.add(host + ":" + port);
            return presented;
        };
        return inventory.build(Snapshot.load(client, KempMock.MGMT_IP), false);
    }

    private static DataIpInfo endpoint(RefreshConfigurationResponse<JsonNode> r, String alias) {
        return r.getDataIpInfo().stream().filter(d -> alias.equals(d.getAlias())).findFirst().orElseThrow();
    }

    @Test
    void factoryCertificateIsReportedFromTheHandshake() throws Exception {
        lm.vs(4, "192.0.2.12", 8443, "tcp", "fresh", true, FACTORY);
        RefreshConfigurationResponse<JsonNode> r = build(Optional.of(FACTORY_CERT));
        assertEquals(List.of("192.0.2.12:8443"), lookups);
        assertEquals("8443:" + Inventory.FACTORY_CERTIFICATE + "-4", endpoint(r, "fresh").getPortWithCert());
        assertEquals("8443:kemp-factory-certificate-4", endpoint(r, "fresh").getPortWithCert());
        Certificate c = r.getCertificates().get(0);
        assertEquals(1, r.getCertificates().size());
        assertEquals("192.0.2.12", c.getIpAddress());
        assertEquals(8443, c.getPort());
        assertEquals("192.0.2.12:8443", c.getIpAndPort());
        assertEquals(Pem.toPem(FACTORY_CERT), c.getCertificate());
        assertFalse(c.isSni());
        assertEquals("kemp-factory-certificate-4", c.getServerParam());
        assertEquals("Kemp Factory Example", c.getDomainName());
        assertEquals(List.of(), lm.requests("readcert"), "the factory value is never read via the API");
    }

    @Test
    void unreachableFactoryServiceStaysAnUnsecuredEndpoint() throws Exception {
        lm.vs(4, "192.0.2.12", 443, "tcp", "fresh", true, FACTORY);
        RefreshConfigurationResponse<JsonNode> r = build(Optional.empty());
        assertEquals("443:", endpoint(r, "fresh").getPortWithCert());
        assertEquals(List.of(), r.getCertificates());
        assertEquals(List.of("192.0.2.12:443"), lookups);
    }

    /** Each factory service gets its own identifier, so TLM keeps the endpoints apart. */
    @Test
    void factoryIdentifiersAreUniquePerVirtualService() throws Exception {
        lm.vs(3, "192.0.2.12", 443, "tcp", "f3", true, FACTORY).vs(7, "192.0.2.13", 443, "tcp", "f7", true, FACTORY);
        RefreshConfigurationResponse<JsonNode> r = build(Optional.of(FACTORY_CERT));
        assertEquals("443:kemp-factory-certificate-3", endpoint(r, "f3").getPortWithCert());
        assertEquals("443:kemp-factory-certificate-7", endpoint(r, "f7").getPortWithCert());
        assertEquals(List.of("kemp-factory-certificate-3", "kemp-factory-certificate-7"),
                r.getCertificates().stream().map(Certificate::getServerParam).toList());
    }

    /** Within the handshake budget every factory service is looked up (the cut-off after 30 s is not tested here). */
    @Test
    void allFactoryServicesAreLookedUpWithinTheBudget() throws Exception {
        for (int i = 0; i < 12; i++) {
            lm.vs(30 + i, "192.0.2." + (100 + i), 443, "tcp", "f" + i, true, FACTORY);
        }
        RefreshConfigurationResponse<JsonNode> r = build(Optional.of(FACTORY_CERT));
        assertEquals(12, lookups.size());
        assertEquals(12, r.getCertificates().size());
        assertTrue(Inventory.HANDSHAKE_BUDGET.compareTo(java.time.Duration.ofSeconds(5)) > 0, "budget too small for 12 lookups");
    }

    /**
     * Kemp's built-in certificate is issued by a Kemp CA ("CN=KEMP Technologies"), not self-signed, with the
     * appliance IP as CN. Any presented certificate on a factory-only service must be reported.
     */
    @Test
    void caIssuedFactoryCertificateIsReported() throws Exception {
        TestPki.Ca kemp = new TestPki.Ca("KEMP Technologies");
        X509Certificate builtIn = kemp.issue(TestPki.rsa(2048).getPublic(), "192.0.2.12", BigInteger.valueOf(77));
        lm.vs(4, "192.0.2.12", 443, "tcp", "fresh", true, FACTORY);
        RefreshConfigurationResponse<JsonNode> r = build(Optional.of(builtIn));
        assertEquals("443:kemp-factory-certificate-4", endpoint(r, "fresh").getPortWithCert());
        Certificate c = r.getCertificates().get(0);
        assertEquals(Pem.toPem(builtIn), c.getCertificate());
        assertEquals("192.0.2.12", c.getDomainName());
        assertEquals("kemp-factory-certificate-4", c.getServerParam());
    }

    @Test
    void lookupOnlyForFactoryCertificateServices() throws Exception {
        lm.vs(1, "192.0.2.10", 443, "tcp", "app", true, "app-cert").readcert("app-cert", TestPki.pem(APP))
                .vs(2, "192.0.2.11", 443, "tcp", "noCert", true, null)
                .vs(3, "192.0.2.13", 80, "tcp", "plain", false, FACTORY)
                .vs(5, "192.0.2.14", 443, "tcp", "mixed", true, FACTORY + " app-cert");
        RefreshConfigurationResponse<JsonNode> r = build(Optional.of(FACTORY_CERT));
        assertEquals(List.of(), lookups, "no handshake for services with own certificates, without SSL or without any");
        assertTrue(r.getCertificates().stream().noneMatch(c -> c.getServerParam().startsWith(Inventory.FACTORY_CERTIFICATE)));
        assertEquals("443:" + FACTORY + ",app-cert", endpoint(r, "mixed").getPortWithCert());
    }

    @Test
    void realLookupAgainstLocalTlsServer() throws Exception {
        try (LocalServers.Tls server = new LocalServers.Tls("Kemp Factory Local")) {
            lm.vs(4, "127.0.0.1", server.port(), "tcp", "fresh", true, FACTORY);
            RefreshConfigurationResponse<JsonNode> r = new Inventory(client).build(Snapshot.load(client, KempMock.MGMT_IP), false);
            assertEquals(Pem.toPem(server.certificate), r.getCertificates().get(0).getCertificate());
            assertEquals(server.port() + ":kemp-factory-certificate-4", endpoint(r, "fresh").getPortWithCert());
        }
    }

    @Test
    void realLookupAgainstClosedPortIsEmpty() throws Exception {
        int port = LocalServers.closedPort();
        lm.vs(4, "127.0.0.1", port, "tcp", "fresh", true, FACTORY);
        RefreshConfigurationResponse<JsonNode> r = new Inventory(client).build(Snapshot.load(client, KempMock.MGMT_IP), false);
        assertEquals(port + ":", endpoint(r, "fresh").getPortWithCert());
        assertEquals(List.of(), r.getCertificates());
    }
}
