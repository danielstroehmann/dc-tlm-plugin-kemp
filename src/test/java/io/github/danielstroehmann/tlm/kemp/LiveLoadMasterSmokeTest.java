package io.github.danielstroehmann.tlm.kemp;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import java.nio.file.Path;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import com.digicert.tlm.workflows.automation.dto.RefreshConfigurationResponse;
import com.digicert.tlm.workflows.automation.dto.TestConnectionResponse;
import com.fasterxml.jackson.databind.JsonNode;

import io.github.danielstroehmann.tlm.kemp.pki.FlowKeyStore;

/**
 * Smoke test against a LIVE LoadMaster, read-only (testConnection + refreshConfiguration). Runs only when
 * {@code KEMP_SMOKE_HOST}, {@code KEMP_SMOKE_PORT} and {@code KEMP_SMOKE_APIKEY} are set; skipped otherwise.
 * <p>
 * Example: {@code KEMP_SMOKE_HOST=lm.example.com KEMP_SMOKE_PORT=443 KEMP_SMOKE_APIKEY=... mvn -s settings.xml test
 * -Dtest=LiveLoadMasterSmokeTest}
 */
@SuppressWarnings("unchecked")
class LiveLoadMasterSmokeTest {

    @TempDir
    Path tmp;
    private KempLoadMasterPlugin plugin;

    @BeforeEach
    void configure() {
        String host = System.getenv("KEMP_SMOKE_HOST");
        String port = System.getenv("KEMP_SMOKE_PORT");
        String apiKey = System.getenv("KEMP_SMOKE_APIKEY");
        assumeTrue(notBlank(host) && notBlank(port) && notBlank(apiKey),
                "KEMP_SMOKE_HOST/KEMP_SMOKE_PORT/KEMP_SMOKE_APIKEY not set: live smoke test skipped");
        plugin = new KempLoadMasterPlugin(MockedPlugin.config(host, port, apiKey), new FlowKeyStore(tmp));
    }

    @Test
    void testConnectionSucceeds() throws Exception {
        TestConnectionResponse<JsonNode> r = (TestConnectionResponse<JsonNode>) plugin.testConnection(null);
        assertNotNull(r);
        assertTrue(r.isActive(), "connector not active: " + r.getErrors());
    }

    @Test
    void refreshConfigurationReturnsConsistentInventory() throws Exception {
        RefreshConfigurationResponse<JsonNode> r = (RefreshConfigurationResponse<JsonNode>) plugin.refreshConfiguration(null);
        assertNotNull(r.getAutomationInfo());
        assertEquals("Kemp LoadMaster", r.getAutomationInfo().getOsName());
        assertFalse(r.getAutomationInfo().getOsVersion().isBlank());
        assertFalse(r.getAutomationInfo().getManagementIp().isBlank());
        assertNotNull(r.getDataIpInfo());
        assertNotNull(r.getCertificates());
        for (var ep : r.getDataIpInfo()) {
            assertEquals("default", ep.getPartition());
            assertTrue(ep.getPort() > 0 && ep.getPort() <= 65535);
            assertFalse(ep.getAlias() == null || ep.getAlias().isBlank());
            assertTrue(ep.getPortWithCert().startsWith(ep.getPort() + ":"));
        }
        for (var c : r.getCertificates()) {
            assertEquals(c.getIpAddress() + ":" + c.getPort(), c.getIpAndPort());
            assertFalse(c.getServerParam() == null || c.getServerParam().isBlank());
        }
    }

    private static boolean notBlank(String s) {
        return s != null && !s.isBlank();
    }
}
