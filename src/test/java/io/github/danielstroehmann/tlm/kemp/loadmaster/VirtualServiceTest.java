package io.github.danielstroehmann.tlm.kemp.loadmaster;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;

import org.junit.jupiter.api.Test;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

class VirtualServiceTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private static VirtualService vs(String json) throws Exception {
        return VirtualService.from(MAPPER.readTree(json));
    }

    @Test
    void parsesTopLevelSslService() throws Exception {
        VirtualService v = vs("{\"Index\":1,\"VSAddress\":\"192.0.2.10\",\"VSPort\":\"443\",\"Protocol\":\"tcp\","
                + "\"NickName\":\"app\",\"SSLAcceleration\":true,\"CertFile\":\"app-cert\",\"MasterVSID\":0}");
        assertEquals("1", v.index());
        assertEquals("192.0.2.10", v.address());
        assertEquals(443, v.port());
        assertEquals("tcp", v.protocol());
        assertEquals("app", v.nickName());
        assertTrue(v.ssl());
        assertEquals(List.of("app-cert"), v.certificates());
        assertFalse(v.factoryCertificate());
        assertFalse(v.subVs());
        assertTrue(v.manageable());
        assertEquals("192.0.2.10:443", v.endpoint());
    }

    @Test
    void splitsSpaceSeparatedCertificateList() throws Exception {
        VirtualService v = vs("{\"Index\":4,\"VSAddress\":\"192.0.2.11\",\"VSPort\":\"443\",\"SSLAcceleration\":true,"
                + "\"CertFile\":\" portal  shop wildcard_2025 \",\"MasterVSID\":0}");
        assertEquals(List.of("portal", "shop", "wildcard_2025"), v.certificates());
        assertFalse(v.factoryCertificate());
    }

    @Test
    void factoryCertificateIsRecognised() throws Exception {
        VirtualService v = vs("{\"Index\":5,\"VSAddress\":\"192.0.2.12\",\"VSPort\":\"443\",\"SSLAcceleration\":true,"
                + "\"CertFile\":\"0123456789abcdef0123456789abcdef\",\"MasterVSID\":0}");
        assertTrue(v.factoryCertificate());
        assertEquals(List.of(), v.certificates());
        assertTrue(v.manageable());
    }

    @Test
    void thirtyTwoHexAmongOthersIsARealIdentifier() throws Exception {
        VirtualService v = vs("{\"Index\":5,\"VSAddress\":\"192.0.2.12\",\"VSPort\":\"443\",\"SSLAcceleration\":true,"
                + "\"CertFile\":\"0123456789abcdef0123456789abcdef other\",\"MasterVSID\":0}");
        assertFalse(v.factoryCertificate());
        assertEquals(2, v.certificates().size());
    }

    @Test
    void subVsIsNotManageable() throws Exception {
        VirtualService noAddress = vs("{\"Index\":3,\"VSPort\":\"0\",\"NickName\":\"sub\",\"SSLAcceleration\":true,"
                + "\"MasterVSID\":2}");
        assertNull(noAddress.address());
        assertTrue(noAddress.subVs());
        assertFalse(noAddress.manageable());

        VirtualService withMaster = vs("{\"Index\":3,\"VSAddress\":\"192.0.2.13\",\"VSPort\":\"443\",\"SSLAcceleration\":true,"
                + "\"CertFile\":\"x\",\"MasterVSID\":2}");
        assertTrue(withMaster.subVs());
        assertFalse(withMaster.manageable());
    }

    @Test
    void sslOffIsNotManageable() throws Exception {
        VirtualService v = vs("{\"Index\":6,\"VSAddress\":\"192.0.2.14\",\"VSPort\":\"80\",\"SSLAcceleration\":false,"
                + "\"MasterVSID\":0}");
        assertFalse(v.ssl());
        assertFalse(v.manageable());
        assertEquals(List.of(), v.certificates());
    }

    @Test
    void missingOrNonTextualFieldsAreTolerated() throws Exception {
        JsonNode n = MAPPER.readTree("{\"Index\":7,\"VSAddress\":\"192.0.2.15\",\"VSPort\":\"8443\",\"SSLAcceleration\":true,"
                + "\"CertFile\":[\"a\"],\"NickName\":5}");
        VirtualService v = VirtualService.from(n);
        assertEquals(List.of(), v.certificates());
        assertNull(v.nickName());
        assertEquals("tcp", v.protocol());
        assertEquals(8443, v.port());
    }
}
