package io.github.danielstroehmann.tlm.kemp.loadmaster;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import java.util.Optional;
import java.util.Set;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import io.github.danielstroehmann.tlm.kemp.client.KempClient;
import io.github.danielstroehmann.tlm.kemp.client.KempPermissionDeniedException;
import io.github.danielstroehmann.tlm.kemp.testsupport.KempMock;

@org.junit.jupiter.api.Timeout(60)
class SnapshotTest {

    private static VirtualService vs(String index, String ip, int port, String protocol, String nick, boolean ssl,
            String... certs) {
        return new VirtualService(index, ip, port, protocol, nick, ssl, List.of(certs), false, false);
    }

    private static final VirtualService APP = vs("1", "192.0.2.10", 443, "tcp", "app", true, "app-cert");
    private static final VirtualService APP_UDP = vs("2", "192.0.2.10", 443, "udp", "app-quic", true, "app-cert");
    private static final VirtualService DUP_A = vs("3", "192.0.2.11", 443, "tcp", "web", true, "a");
    private static final VirtualService DUP_B = vs("4", "192.0.2.12", 443, "tcp", "web", true, "b");
    private static final VirtualService PLAIN = vs("5", "192.0.2.13", 80, "tcp", "plain", false);
    private static final VirtualService NICK_MGMT = vs("6", "192.0.2.14", 443, "tcp", "management", true, "m");
    private static final VirtualService SUB = new VirtualService("7", null, 0, "tcp", "sub", true, List.of(), false, true);

    private static Snapshot snapshot(VirtualService... services) {
        return new Snapshot(List.of(services), Set.of(), List.of("192.0.2.1", "198.51.100.1", "lm.example.com"), 8443,
                "web-ui", "lm.example.com");
    }

    @Test
    void manageableExcludesSslOffAndSubVs() {
        assertEquals(List.of(APP), snapshot(APP, PLAIN, SUB).manageable());
    }

    @Test
    void aliasIsUniqueNickNameOtherwiseEndpoint() {
        Snapshot s = snapshot(APP, DUP_A, DUP_B, NICK_MGMT);
        assertEquals("app", s.alias(APP));
        assertEquals("192.0.2.11:443", s.alias(DUP_A));
        assertEquals("192.0.2.12:443", s.alias(DUP_B));
        assertEquals("192.0.2.14:443", s.alias(NICK_MGMT), "'management' is reserved for the web UI endpoint");
        assertEquals("192.0.2.13:80", snapshot(new VirtualService("9", "192.0.2.13", 80, "tcp", " ", true, List.of("x"), false,
                false)).alias(new VirtualService("9", "192.0.2.13", 80, "tcp", " ", true, List.of("x"), false, false)));
    }

    @Test
    void resolvesByIpAndPortFirst() {
        Optional<Target> t = snapshot(APP, DUP_A).resolve("192.0.2.10", "443", "default/web");
        assertEquals(new Target.Vs(APP), t.orElseThrow());
    }

    @Test
    void tcpIsPreferredOverUdpOnSameEndpoint() {
        assertEquals(new Target.Vs(APP), snapshot(APP_UDP, APP).resolve("192.0.2.10", " 443 ", null).orElseThrow());
    }

    @Test
    void resolvesByAliasWithAndWithoutPartition() {
        Snapshot s = snapshot(APP, DUP_A, DUP_B);
        assertEquals(new Target.Vs(APP), s.resolve(null, null, "default/app").orElseThrow());
        assertEquals(new Target.Vs(APP), s.resolve("203.0.113.99", "443", "app").orElseThrow());
        assertEquals(new Target.Vs(DUP_B), s.resolve(null, "x", "default/192.0.2.12:443").orElseThrow());
    }

    @Test
    void ambiguousNickNameDoesNotResolve() {
        assertTrue(snapshot(DUP_A, DUP_B).resolve(null, null, "default/web").isEmpty());
    }

    @Test
    void managementByAliasOrByDefaultIpOrConfiguredHostAndWuiPort() {
        Snapshot s = snapshot(APP);
        Target mgmt = new Target.Management();
        assertEquals(mgmt, s.resolve(null, null, "default/management").orElseThrow());
        assertEquals(mgmt, s.resolve("192.0.2.1", "8443", null).orElseThrow());
        assertEquals(mgmt, s.resolve("lm.example.com", "8443", "").orElseThrow(), "configured host");
        assertTrue(s.resolve("198.51.100.1", "8443", null).isEmpty(), "secondary interface is not the web UI");
        assertTrue(s.resolve("192.0.2.1", "443", null).isEmpty(), "other port is not the web UI");
        assertTrue(s.resolve("203.0.113.5", "8443", null).isEmpty());
    }

    @Test
    void managementAliasWinsEvenOverAnEndpointMatch() {
        assertEquals(new Target.Management(), snapshot(APP).resolve("192.0.2.10", "443", "default/management").orElseThrow());
    }

    @Test
    void serviceOnManagementIpAndWuiPortIsNeverTheWebUi() {
        VirtualService onMgmt = vs("8", "192.0.2.1", 8443, "tcp", "mgmt-vs", true, "x");
        assertEquals(new Target.Vs(onMgmt), snapshot(onMgmt).resolve("192.0.2.1", "8443", null).orElseThrow());
        // Even a non-manageable service (SSL off) there blocks the web UI interpretation.
        VirtualService plainOnMgmt = vs("9", "192.0.2.1", 8443, "tcp", "mgmt-plain", false);
        assertTrue(snapshot(plainOnMgmt).resolve("192.0.2.1", "8443", null).isEmpty());
    }

    @Test
    void nonManageableServicesAreNotResolved() {
        Snapshot s = snapshot(APP, PLAIN, SUB);
        assertTrue(s.resolve("192.0.2.13", "80", "default/plain").isEmpty());
        assertTrue(s.resolve(null, null, "default/sub").isEmpty());
    }

    @Test
    void nothingGivenResolvesNothing() {
        assertTrue(snapshot(APP).resolve(null, null, null).isEmpty());
        assertTrue(snapshot(APP).resolve("192.0.2.10", "not-a-port", null).isEmpty());
    }

    // ---- load() against the mock LoadMaster ----------------------------------------------------------------

    private KempMock lm;
    private KempClient client;

    @BeforeEach
    void start() {
        lm = new KempMock().defaults();
        client = KempClient.forBaseUrl(lm.baseUrl(), "test-key", 0);
    }

    @AfterEach
    void stop() {
        client.close();
        lm.close();
    }

    @Test
    void loadReadsServicesAddressesAdminCertAndAcme() throws Exception {
        lm.vs(1, "192.0.2.10", 443, "tcp", "app", true, "app-cert").subVs(2, 1, "sub", true).acme("acme-cert");
        Snapshot s = Snapshot.load(client, "lm.example.com");
        assertEquals(2, s.virtualServices().size());
        assertEquals(1, s.manageable().size());
        assertEquals(List.of("192.0.2.1", "198.51.100.1", "lm.example.com"), s.managementAddresses());
        assertEquals("192.0.2.1", s.managementIp());
        assertEquals(8443, s.wuiPort());
        assertEquals("web-ui", s.adminCertificate());
        assertEquals(Set.of("acme-cert"), s.acmeCertificates());
    }

    /**
     * Only the default interface IP or the configured host may mean the web UI. When the configured host is the
     * default interface IP, a secondary interface IP must not be taken for the web UI.
     */
    @Test
    void secondaryInterfaceIsNotWebUiWhenConfiguredHostIsDefaultIp() throws Exception {
        Snapshot s = Snapshot.load(client, "192.0.2.1");
        assertEquals(new Target.Management(), s.resolve("192.0.2.1", "8443", null).orElseThrow());
        assertTrue(s.resolve("198.51.100.1", "8443", null).isEmpty(), "secondary interface resolved as web UI");
    }

    @Test
    void configuredHostnameMeansWebUi() throws Exception {
        Snapshot s = Snapshot.load(client, "lm.example.com");
        assertEquals(new Target.Management(), s.resolve("lm.example.com", "8443", null).orElseThrow());
        assertTrue(s.resolve("198.51.100.1", "8443", null).isEmpty());
    }

    @Test
    void configuredIpIsNotDuplicated() throws Exception {
        assertEquals(List.of("192.0.2.1", "198.51.100.1"), Snapshot.load(client, "192.0.2.1").managementAddresses());
    }

    @Test
    void adminCertificateManageableUnlessAcme() {
        assertTrue(snapshot(APP).adminCertificateManageable());
        assertTrue(new Snapshot(List.of(), Set.of("acme-cert"), List.of("192.0.2.1"), 8443, null, "192.0.2.1").adminCertificateManageable());
        assertFalse(new Snapshot(List.of(), Set.of("web-ui"), List.of("192.0.2.1"), 8443, "web-ui", "192.0.2.1").adminCertificateManageable());
    }

    @Test
    void transportErrorOnAcmeListingPropagates() {
        lm.onHttp("listacmecert", 503, "text/html", "<html>503</html>");
        assertThrows(io.github.danielstroehmann.tlm.kemp.client.KempApiException.class, () -> Snapshot.load(client, "192.0.2.1"));
    }

    @Test
    void noAdminCertificateBecomesNull() throws Exception {
        lm.get("admincert", "\"No Admin Certificate assigned\"");
        assertNull(Snapshot.load(client, "192.0.2.1").adminCertificate());
    }

    @Test
    void permissionDeniedOnAcmeListingPropagates() {
        lm.deny("listacmecert");
        assertThrows(KempPermissionDeniedException.class, () -> Snapshot.load(client, "192.0.2.1"));
    }

    @Test
    void targetTypes() {
        assertInstanceOf(Target.Management.class, snapshot(APP).resolve(null, null, "management").orElseThrow());
        assertInstanceOf(Target.Vs.class, snapshot(APP).resolve("192.0.2.10", "443", null).orElseThrow());
    }
}
