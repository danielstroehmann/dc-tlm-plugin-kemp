package io.github.danielstroehmann.tlm.kemp;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import com.digicert.tlm.plugin.model.PluginConfiguration;
import com.digicert.tlm.workflows.WorkflowExecutionException;
import com.digicert.tlm.workflows.automation.dto.GenerateCsrResponse;
import com.digicert.tlm.workflows.automation.dto.TestConnectionResponse;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.JavaType;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;

import io.github.danielstroehmann.tlm.kemp.pki.FlowKeyStore;
import io.github.danielstroehmann.tlm.kemp.testsupport.KempMock;
import io.github.danielstroehmann.tlm.kemp.testsupport.TestPki;

/**
 * TLM delivers "sensitive" settings Base64-encoded. The plugin decodes them, trims invisible edge characters and uses
 * the same result for LoadMaster calls and the key store password. Only made-up keys are used here.
 */
@Timeout(60)
@SuppressWarnings("unchecked")
class ApiKeyEncodingTest {

    /** Made-up 44-character key in the style of a Kemp API key. */
    private static final String KEY = "Ab3dEf6hIj9kLm2nOp5qRs8tUv1wXy4zAb7cDe0fGh3i";
    private static final TestPki.Ca CA = new TestPki.Ca("Encoding");

    @TempDir
    Path tmp;

    private static String b64(String s) {
        return Base64.getEncoder().encodeToString(s.getBytes(StandardCharsets.UTF_8));
    }

    private TestConnectionResponse<JsonNode> connect(KempMock lm, String configured) throws Exception {
        KempLoadMasterPlugin plugin = new KempLoadMasterPlugin(
                MockedPlugin.config("127.0.0.1", String.valueOf(lm.server.httpsPort()), configured), new FlowKeyStore(tmp));
        return (TestConnectionResponse<JsonNode>) plugin.testConnection(null);
    }

    // ---- (1) / (3) authentication against a LoadMaster that expects the plain key ---------------------------

    @Test
    void base64EncodedKeyAsTlmSendsItAuthenticates() throws Exception {
        String encoded = b64(KEY);
        assertEquals(60, encoded.length());
        assertTrue(encoded.endsWith("="), "TLM-style padding expected: " + encoded);
        try (KempMock lm = new KempMock(true).defaults().requireApiKey(KEY)) {
            assertTrue(connect(lm, encoded).isActive());
            assertEquals(List.of(KEY), lm.requests("get").stream().map(n -> n.path("apikey").asText()).distinct().toList());
        }
    }

    @ParameterizedTest
    @ValueSource(strings = { " %s\n", "\t%s\r\n", "\u200B%s\uFEFF", "\u00A0 %s \u00A0", "\uFEFF\n\u200B %s\u200B\n" })
    void encodedKeyWithSurroundingInvisibleCharactersAuthenticates(String template) throws Exception {
        try (KempMock lm = new KempMock(true).defaults().requireApiKey(KEY)) {
            assertTrue(connect(lm, String.format(template, b64(KEY))).isActive());
        }
    }

    @ParameterizedTest
    @ValueSource(strings = { "\u00A0%s", "%s\u200B", "\uFEFF%s", " \u200B\u00A0%s\n" })
    void plainKeyWithInvisibleEdgeCharactersAuthenticates(String template) throws Exception {
        try (KempMock lm = new KempMock(true).defaults().requireApiKey(KEY)) {
            assertTrue(connect(lm, String.format(template, KEY)).isActive());
        }
    }

    /** The user pasted the key with a trailing newline/space into TLM, which then Base64-encoded that value. */
    @ParameterizedTest
    @ValueSource(strings = { " %s", "%s\n", "\t%s\r\n", "%s " })
    void decodedKeyWithSurroundingWhitespaceAuthenticates(String template) throws Exception {
        try (KempMock lm = new KempMock(true).defaults().requireApiKey(KEY)) {
            assertTrue(connect(lm, b64(String.format(template, KEY))).isActive());
        }
    }

    // ---- (2) plain keys are not decoded --------------------------------------------------------------------

    @Test
    void randomPlainKemp44CharacterKeysAreNotDecoded() {
        SecureRandom random = new SecureRandom();
        String alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
        for (int i = 0; i < 500; i++) {
            StringBuilder sb = new StringBuilder();
            for (int j = 0; j < 44; j++) {
                sb.append(alphabet.charAt(random.nextInt(alphabet.length())));
            }
            String key = sb.toString();
            assertEquals(Optional.empty(), KempLoadMasterPlugin.decodeTlmEncoding(key), key);
        }
        assertEquals(Optional.empty(), KempLoadMasterPlugin.decodeTlmEncoding(KEY));
    }

    @Test
    void plainKeyAuthenticatesUnchanged() throws Exception {
        try (KempMock lm = new KempMock(true).defaults().requireApiKey(KEY)) {
            assertTrue(connect(lm, KEY).isActive());
        }
    }

    @Test
    void decodeTlmEncodingRules() {
        assertEquals(Optional.of(KEY), KempLoadMasterPlugin.decodeTlmEncoding(b64(KEY)));
        assertEquals(Optional.of("a"), KempLoadMasterPlugin.decodeTlmEncoding("YQ=="));
        assertEquals(Optional.empty(), KempLoadMasterPlugin.decodeTlmEncoding(""), "empty result");
        assertEquals(Optional.empty(), KempLoadMasterPlugin.decodeTlmEncoding("not base64!"), "invalid Base64");
        assertEquals(Optional.empty(), KempLoadMasterPlugin.decodeTlmEncoding("-_-_"), "URL-safe, but decodes to non-ASCII");
        assertEquals(Optional.empty(), KempLoadMasterPlugin.decodeTlmEncoding(
                Base64.getEncoder().encodeToString(new byte[] { 0x00, 0x7F, (byte) 0xFF, 0x41 })), "binary result");
        assertEquals(Optional.empty(), KempLoadMasterPlugin.decodeTlmEncoding(b64("ab cd")), "space inside is not printable");
        assertEquals(Optional.empty(), KempLoadMasterPlugin.decodeTlmEncoding(b64("schl\u00FCssel")), "non-ASCII");
    }

    @Test
    void onlyCanonicalBase64IsDecoded() {
        assertEquals(Optional.of("A"), KempLoadMasterPlugin.decodeTlmEncoding("QQ=="));
        assertEquals(Optional.of("A"), KempLoadMasterPlugin.decodeTlmEncoding("QQ"), "unpadded canonical input");
        assertEquals(Optional.empty(), KempLoadMasterPlugin.decodeTlmEncoding("QR=="), "non-zero padding bits");
        assertEquals(Optional.empty(), KempLoadMasterPlugin.decodeTlmEncoding("QR"));
        assertEquals(Optional.empty(), KempLoadMasterPlugin.decodeTlmEncoding("QQ="), "wrong padding length");
        assertEquals(Optional.empty(), KempLoadMasterPlugin.decodeTlmEncoding("QQ==="));
        String encoded = b64(KEY);
        assertEquals(Optional.empty(), KempLoadMasterPlugin.decodeTlmEncoding(encoded.substring(0, 20) + "\n"
                + encoded.substring(20)), "line breaks inside are not canonical");
        assertEquals(Optional.empty(), KempLoadMasterPlugin.decodeTlmEncoding(encoded.substring(0, 20) + " "
                + encoded.substring(20)));
    }

    @Test
    void urlSafeBase64IsDecoded() {
        String key = "Key~~~>>>???-end"; // standard encoding contains '+' and '/'
        String standard = b64(key);
        assertTrue(standard.contains("+") || standard.contains("/"), standard);
        String urlSafe = Base64.getUrlEncoder().encodeToString(key.getBytes(StandardCharsets.UTF_8));
        assertTrue(urlSafe.contains("-") || urlSafe.contains("_"), urlSafe);
        assertEquals(Optional.of(key), KempLoadMasterPlugin.decodeTlmEncoding(standard));
        assertEquals(Optional.of(key), KempLoadMasterPlugin.decodeTlmEncoding(urlSafe));
        assertEquals(Optional.of(key), KempLoadMasterPlugin.decodeTlmEncoding(
                Base64.getUrlEncoder().withoutPadding().encodeToString(key.getBytes(StandardCharsets.UTF_8))));
        String mixed = standard.replaceFirst("[+/]", standard.contains("+") ? "-" : "_");
        if (!mixed.equals(standard) && (mixed.contains("+") || mixed.contains("/"))) {
            assertEquals(Optional.empty(), KempLoadMasterPlugin.decodeTlmEncoding(mixed), "mixed alphabets: " + mixed);
        }
    }

    @Test
    void urlSafeEncodedKeyAuthenticates() throws Exception {
        String key = "Key~~~>>>???-end";
        try (KempMock lm = new KempMock(true).defaults().requireApiKey(key)) {
            assertTrue(connect(lm, " " + Base64.getUrlEncoder().encodeToString(key.getBytes(StandardCharsets.UTF_8)) + "\n")
                    .isActive());
        }
    }

    @ParameterizedTest
    @ValueSource(strings = { " %s\n", "\u00A0%s\u00A0", "\uFEFF%s", "%s\u200B\r\n", "\u2007\u202F%s\u2060" })
    void decodedValueIsTrimmedBeforeTheAsciiCheck(String template) {
        assertEquals(Optional.of(KEY), KempLoadMasterPlugin.decodeTlmEncoding(b64(String.format(template, KEY))));
    }

    @Test
    void decodedValueWithInnerWhitespaceIsNotAKey() {
        assertEquals(Optional.empty(), KempLoadMasterPlugin.decodeTlmEncoding(b64("Ab3d Ef6h")));
        assertEquals(Optional.empty(), KempLoadMasterPlugin.decodeTlmEncoding(b64(" \u00A0\n")), "empty after trimming");
    }

    @ParameterizedTest
    @ValueSource(strings = { "\u00A0", "\u2007", "\u202F", "\u200B", "\u200C", "\u200D", "\u2060", "\uFEFF", "\u3000",
            "\u2028", "\u2029", "\u000B", "\u001F" })
    void trimInvisibleRemovesEdgeCodePoint(String c) {
        assertEquals(KEY, KempLoadMasterPlugin.trimInvisible(c + KEY + c));
        assertEquals(KEY, KempLoadMasterPlugin.trimInvisible(c + " " + c + KEY + "\n" + c + "\t"));
    }

    @ParameterizedTest
    @ValueSource(strings = { "\u2007%s", "%s\u202F", "\u200C%s\u200D", "\u2060%s\uFEFF" })
    void plainKeyWithMoreInvisibleCodePointsAuthenticates(String template) throws Exception {
        try (KempMock lm = new KempMock(true).defaults().requireApiKey(KEY)) {
            assertTrue(connect(lm, String.format(template, KEY)).isActive());
        }
    }

    @Test
    void trimInvisibleRules() {
        assertEquals("k", KempLoadMasterPlugin.trimInvisible(" \t\r\n\u00A0\u200B\uFEFFk\uFEFF\u200B\u00A0\n "));
        assertEquals("a b", KempLoadMasterPlugin.trimInvisible("\u200B a b \u00A0"), "inner characters stay");
        assertEquals("a\u200Bb", KempLoadMasterPlugin.trimInvisible("a\u200Bb"));
        assertEquals("", KempLoadMasterPlugin.trimInvisible("\u00A0\u200B\uFEFF \n"));
    }

    // ---- whitespace / invisible-only keys ------------------------------------------------------------------

    /** A key consisting only of invisible characters is as missing as a blank one: it must never be sent or used. */
    @ParameterizedTest
    @ValueSource(strings = { "\u00A0", "\u200B", "\uFEFF\u00A0 \n" })
    void invisibleOnlyKeyIsRejectedAsMissing(String configured) throws Exception {
        try (KempMock lm = new KempMock(true).defaults()) {
            FlowKeyStore store = new FlowKeyStore(tmp.resolve("keys"));
            KempLoadMasterPlugin plugin = new KempLoadMasterPlugin(
                    MockedPlugin.config("127.0.0.1", String.valueOf(lm.server.httpsPort()), configured), store);
            WorkflowExecutionException e = assertThrows(WorkflowExecutionException.class, () -> plugin.testConnection(null));
            assertTrue(e.getMessage().contains("API key is required"), e.getMessage());
            assertEquals(0, lm.server.getAllServeEvents().size(), "an empty API key was sent to the LoadMaster");
            assertThrows(WorkflowExecutionException.class, () -> plugin.generateCsr(
                    MockedPlugin.csrRequest(UUID.randomUUID().toString(), "CN=www.example.com", "", "RSA", "2048")));
            assertFalse(java.nio.file.Files.exists(tmp.resolve("keys")), "key stored with an empty password");
        }
    }

    // ---- (4) generateCsr and installCertificate share the store password -----------------------------------

    @ParameterizedTest
    @ValueSource(booleans = { true, false })
    void encodedAndPlainKeyShareTheStorePassword(boolean encodedAtCsr) throws Exception {
        String encoded = " " + b64(KEY) + "\n";
        FlowKeyStore store = new FlowKeyStore(tmp.resolve("keys"));
        String flow = UUID.randomUUID().toString();
        try (KempMock lm = new KempMock().defaults()) {
            lm.vs(3, "192.0.2.12", 443, "tcp", "fresh", true, "0123456789abcdef0123456789abcdef");
            MockedPlugin csrPlugin = new MockedPlugin(lm, encodedAtCsr ? encoded : KEY, store);
            MockedPlugin installPlugin = new MockedPlugin(lm, encodedAtCsr ? KEY : encoded, store);
            GenerateCsrResponse<JsonNode> csr = (GenerateCsrResponse<JsonNode>) csrPlugin
                    .generateCsr(MockedPlugin.csrRequest(flow, "CN=fresh.example.com", "", "RSA", "2048"));
            store.load(flow, KEY.toCharArray()); // protected with the decoded key
            assertThrows(java.security.GeneralSecurityException.class, () -> store.load(flow, b64(KEY).toCharArray()));

            X509Certificate leaf = CA.issueFromCsr(csr.getCsr(), BigInteger.valueOf(41));
            ObjectNode install = MockedPlugin.MAPPER.createObjectNode().put("flowId", flow).put("ipAddress", "192.0.2.12")
                    .put("port", "443").put("certificateChain", TestPki.pem(leaf, CA.issuing));
            installPlugin.installCertificate(install);
            assertEquals(1, lm.writes("addcert").size());
            assertFalse(store.exists(flow));
        }
    }

    // ---- (6) configuration mapping as the SDK does it ------------------------------------------------------

    /** Same mapping as PluginUtils.getPluginConfiguration: args map \u2192 bytes \u2192 PluginConfiguration&lt;T&gt;. */
    private static PluginConfiguration<KempConfiguration> sdkMapping(Map<String, Object> args) throws Exception {
        ObjectMapper mapper = new ObjectMapper().configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
        JavaType type = mapper.getTypeFactory().constructParametricType(PluginConfiguration.class, KempConfiguration.class);
        return mapper.readValue(mapper.writeValueAsBytes(args), type);
    }

    @Test
    void tlmConfigArgsMapAndUnmappedNamesAreReported() throws Exception {
        Map<String, Object> args = new LinkedHashMap<>();
        args.put("name", "Custom");
        args.put("version", "0.2.0");
        args.put("baseRestApiUrl", null);
        args.put("plugin_upgrade", "UNMAPPED-VALUE-MARKER-7x");
        args.put("managementHost", "lm.example.com");
        args.put("managementPort", "443");
        args.put("apiKey", b64(KEY));
        PluginConfiguration<KempConfiguration> pc = sdkMapping(args);
        assertEquals("Custom", pc.getName());
        assertEquals("0.2.0", pc.getVersion());
        KempConfiguration c = pc.getExtendedConfig();
        assertEquals("lm.example.com", c.getManagementHost());
        assertEquals("443", c.getManagementPort());
        assertEquals(b64(KEY), c.getApiKey());
        assertEquals(Set.of("baseRestApiUrl", "plugin_upgrade"), c.unmappedSettingNames());
        // Values of unmapped settings are never retained (nor is the key printed).
        String dump = new ObjectMapper().writeValueAsString(c) + c + pc;
        assertFalse(dump.contains("UNMAPPED-VALUE-MARKER-7x"), dump);
        for (java.lang.reflect.Field f : KempConfiguration.class.getDeclaredFields()) {
            f.setAccessible(true);
            assertFalse(String.valueOf(f.get(c)).contains("UNMAPPED-VALUE-MARKER-7x"), f.getName());
        }
        assertFalse((c.toString() + pc).contains(b64(KEY)), "toString must not contain the key");
    }

    @Test
    void configWithoutExtraSettingsHasNoUnmappedNames() throws Exception {
        Map<String, Object> args = new LinkedHashMap<>();
        args.put("name", "Custom");
        args.put("version", "0.2.0");
        args.put("managementHost", "lm.example.com");
        args.put("managementPort", "443");
        args.put("apiKey", KEY);
        assertEquals(Set.of(), sdkMapping(args).getExtendedConfig().unmappedSettingNames());
        assertTrue(new KempConfiguration().unmappedSettingNames().isEmpty());
    }

    @Test
    void unmappedSettingNamesIsAnUnmodifiableCopy() throws Exception {
        Map<String, Object> args = new LinkedHashMap<>();
        args.put("plugin_upgrade", "true");
        KempConfiguration c = sdkMapping(args).getExtendedConfig();
        assertThrows(UnsupportedOperationException.class, () -> c.unmappedSettingNames().add("x"));
    }

    // ---- (7) nonPrintable ----------------------------------------------------------------------------------

    @Test
    void nonPrintableListsCodePointsAndPositions() {
        assertEquals("none", KempLoadMasterPlugin.nonPrintable(KEY));
        assertEquals("none", KempLoadMasterPlugin.nonPrintable(""));
        assertEquals("none", KempLoadMasterPlugin.nonPrintable("!~"));
        assertEquals("[U+0020 at 0, U+0009 at 2, U+000A at 4]", KempLoadMasterPlugin.nonPrintable(" a\tb\n"));
        assertEquals("[U+000D at 1, U+000A at 2]", KempLoadMasterPlugin.nonPrintable("k\r\n"));
        assertEquals("[U+00A0 at 0, U+200B at 2, U+FEFF at 3]", KempLoadMasterPlugin.nonPrintable("\u00A0k\u200B\uFEFF"));
        assertEquals("[U+007F at 1, U+0000 at 2]", KempLoadMasterPlugin.nonPrintable("k\u007F\u0000"));
        assertEquals("[U+00FC at 1]", KempLoadMasterPlugin.nonPrintable("s\u00FC"));
    }

    @Test
    void nonPrintableNeverRevealsPrintableCharacters() {
        String out = KempLoadMasterPlugin.nonPrintable(" " + KEY + "\n");
        assertFalse(out.contains(KEY.substring(0, 4)), out);
        assertEquals("[U+0020 at 0, U+000A at " + (KEY.length() + 1) + "]", out);
    }
}
