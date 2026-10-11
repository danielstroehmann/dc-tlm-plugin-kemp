package io.github.danielstroehmann.tlm.kemp.pki;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import java.io.IOException;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.attribute.FileTime;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.stream.Stream;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullSource;
import org.junit.jupiter.params.provider.ValueSource;

import io.github.danielstroehmann.tlm.kemp.testsupport.TestPki;

class FlowKeyStoreTest {

    private static final String FLOW = "3f2c1d7e-8a9b-4c0d-9e1f-a2b3c4d5e6f7";
    private static final char[] PASSWORD = "test-password-not-a-secret".toCharArray();
    private static final KeyPair RSA = TestPki.rsa(2048);

    @TempDir
    Path tmp;

    private Path base() {
        return tmp.resolve("store");
    }

    @Test
    void savesAndLoadsRsaKey() throws Exception {
        FlowKeyStore store = new FlowKeyStore(base());
        store.save(FLOW, RSA.getPrivate(), PASSWORD);
        PrivateKey loaded = store.load(FLOW, PASSWORD);
        assertArrayEquals(RSA.getPrivate().getEncoded(), loaded.getEncoded());
        assertEquals("RSA", loaded.getAlgorithm());
    }

    @Test
    void savesAndLoadsEcKey() throws Exception {
        FlowKeyStore store = new FlowKeyStore(base());
        KeyPair ec = TestPki.ec("secp384r1");
        store.save(FLOW, ec.getPrivate(), PASSWORD);
        PrivateKey loaded = store.load(FLOW, PASSWORD);
        // The PKCS#8 encoding may differ (optional public key / parameters), the key itself must not.
        assertEquals(((java.security.interfaces.ECPrivateKey) ec.getPrivate()).getS(),
                ((java.security.interfaces.ECPrivateKey) loaded).getS());
        java.security.Signature signer = java.security.Signature.getInstance("SHA256withECDSA");
        signer.initSign(loaded);
        signer.update(new byte[] { 1, 2, 3 });
        java.security.Signature verifier = java.security.Signature.getInstance("SHA256withECDSA");
        verifier.initVerify(ec.getPublic());
        verifier.update(new byte[] { 1, 2, 3 });
        assertTrue(verifier.verify(signer.sign()));
    }

    /** The key read back for installCertificate must be recognised as the key of its certificate (RSA and EC). */
    @Test
    void loadedKeysMatchTheirCertificates() throws Exception {
        TestPki.Ca ca = new TestPki.Ca("Store");
        FlowKeyStore store = new FlowKeyStore(base());
        store.save(FLOW, RSA.getPrivate(), PASSWORD);
        assertTrue(Pem.keyMatches(store.load(FLOW, PASSWORD),
                ca.issue(RSA.getPublic(), "rsa.example.com", java.math.BigInteger.ONE)), "RSA");

        KeyPair ec = TestPki.ec("secp256r1");
        store.save(FLOW, ec.getPrivate(), PASSWORD);
        PrivateKey loaded = store.load(FLOW, PASSWORD);
        assertTrue(Pem.keyMatches(loaded, ca.issue(ec.getPublic(), "ec.example.com", java.math.BigInteger.TWO)),
                "EC key loaded from the store (algorithm '" + loaded.getAlgorithm() + "') not matched to its certificate");
    }

    @Test
    void keyIsNotStoredInPlaintext() throws Exception {
        FlowKeyStore store = new FlowKeyStore(base());
        store.save(FLOW, RSA.getPrivate(), PASSWORD);
        byte[] onDisk = Files.readAllBytes(base().resolve(FLOW).resolve("key.bin"));
        byte[] pkcs8 = RSA.getPrivate().getEncoded();
        assertFalse(indexOf(onDisk, java.util.Arrays.copyOfRange(pkcs8, 30, 94)) >= 0, "PKCS#8 bytes found on disk");
        assertFalse(new String(onDisk, java.nio.charset.StandardCharsets.ISO_8859_1)
                .contains(Base64.getEncoder().encodeToString(pkcs8).substring(40, 100)));
        assertFalse(new String(onDisk, java.nio.charset.StandardCharsets.ISO_8859_1).contains(new String(PASSWORD)));
    }

    @Test
    void wrongPasswordFails() throws Exception {
        FlowKeyStore store = new FlowKeyStore(base());
        store.save(FLOW, RSA.getPrivate(), PASSWORD);
        GeneralSecurityException e = assertThrows(GeneralSecurityException.class,
                () -> store.load(FLOW, "other-password".toCharArray()));
        assertTrue(e.getMessage().contains("API key"), e.getMessage());
        assertFalse(e.getMessage().contains("other-password"));
    }

    @Test
    void loadWithoutSavedKeyFails() {
        FlowKeyStore store = new FlowKeyStore(base());
        IOException e = assertThrows(IOException.class, () -> store.load(FLOW, PASSWORD));
        assertTrue(e.getMessage().contains("generateCsr"));
    }

    @Test
    void saveOverwritesPreviousKeyOfSameFlow() throws Exception {
        FlowKeyStore store = new FlowKeyStore(base());
        store.save(FLOW, TestPki.rsa(2048).getPrivate(), PASSWORD);
        store.save(FLOW, RSA.getPrivate(), PASSWORD);
        assertArrayEquals(RSA.getPrivate().getEncoded(), store.load(FLOW, PASSWORD).getEncoded());
    }

    @Test
    void deleteRemovesKeyAndIsIdempotent() throws Exception {
        FlowKeyStore store = new FlowKeyStore(base());
        store.save(FLOW, RSA.getPrivate(), PASSWORD);
        store.delete(FLOW);
        assertFalse(Files.exists(base().resolve(FLOW)));
        assertThrows(IOException.class, () -> store.load(FLOW, PASSWORD));
        store.delete(FLOW); // no exception
    }

    @Test
    void flowsAreIsolated() throws Exception {
        FlowKeyStore store = new FlowKeyStore(base());
        KeyPair other = TestPki.rsa(2048);
        store.save(FLOW, RSA.getPrivate(), PASSWORD);
        store.save("11111111-2222-3333-4444-555555555555", other.getPrivate(), PASSWORD);
        store.delete(FLOW);
        assertArrayEquals(other.getPrivate().getEncoded(),
                store.load("11111111-2222-3333-4444-555555555555", PASSWORD).getEncoded());
    }

    /** OWASP path traversal: the flow ID becomes a directory name and must not escape the store. */
    @ParameterizedTest
    @NullSource
    @ValueSource(strings = { "../../etc", "..", "../../../../tmp/evil", "abc/../../x", "/etc/passwd", "C:\\Windows\\x",
            "flow id with spaces", "abcdefg", "%2e%2e%2f%2e%2e", "abcdefgh\u0000", "abcdefgh.key",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" })
    void invalidFlowIdsAreRejectedEverywhere(String flowId) throws Exception {
        FlowKeyStore store = new FlowKeyStore(base());
        assertThrows(IllegalArgumentException.class, () -> store.save(flowId, RSA.getPrivate(), PASSWORD));
        assertThrows(IllegalArgumentException.class, () -> store.load(flowId, PASSWORD));
        assertThrows(IllegalArgumentException.class, () -> store.delete(flowId));
        try (Stream<Path> all = Files.walk(tmp)) {
            assertEquals(1, all.count(), "nothing may be created for an invalid flow id");
        }
    }

    @Test
    void directoriesAndFileAreOwnerOnly() throws Exception {
        assumeTrue(posix());
        FlowKeyStore store = new FlowKeyStore(base());
        store.save(FLOW, RSA.getPrivate(), PASSWORD);
        assertEquals("rwx------", PosixFilePermissions.toString(Files.getPosixFilePermissions(base())));
        assertEquals("rwx------", PosixFilePermissions.toString(Files.getPosixFilePermissions(base().resolve(FLOW))));
        assertEquals("rw-------",
                PosixFilePermissions.toString(Files.getPosixFilePermissions(base().resolve(FLOW).resolve("key.bin"))));
    }

    @Test
    void existingWorldReadableBaseDirIsTightened() throws Exception {
        assumeTrue(posix());
        Files.createDirectory(base(), PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwxr-xr-x")));
        Files.setPosixFilePermissions(base(), PosixFilePermissions.fromString("rwxrwxrwx"));
        new FlowKeyStore(base()).save(FLOW, RSA.getPrivate(), PASSWORD);
        assertEquals("rwx------", PosixFilePermissions.toString(Files.getPosixFilePermissions(base())));
    }

    @Test
    void symlinkedBaseDirIsRejected() throws Exception {
        Path real = Files.createDirectory(tmp.resolve("elsewhere"));
        Files.createSymbolicLink(base(), real);
        IOException e = assertThrows(IOException.class,
                () -> new FlowKeyStore(base()).save(FLOW, RSA.getPrivate(), PASSWORD));
        assertTrue(e.getMessage().contains("not a directory"));
        try (Stream<Path> s = Files.list(real)) {
            assertEquals(0, s.count());
        }
    }

    @Test
    void symlinkedBaseDirIsNotPurged() throws Exception {
        Path real = Files.createDirectory(tmp.resolve("elsewhere"));
        Path old = Files.createDirectory(real.resolve("aaaaaaaa-0000-0000-0000-00000000000f"));
        Files.setLastModifiedTime(old, FileTime.from(Instant.now().minus(Duration.ofDays(30))));
        Files.createSymbolicLink(base(), real);
        assertThrows(IOException.class, () -> new FlowKeyStore(base()).save(FLOW, RSA.getPrivate(), PASSWORD));
        assertTrue(Files.exists(old), "nothing behind a foreign/symlinked directory may be deleted");
    }

    @Test
    void symlinkedFlowDirIsRejected() throws Exception {
        Path real = Files.createDirectory(tmp.resolve("elsewhere"));
        Files.createDirectory(base());
        Files.createSymbolicLink(base().resolve(FLOW), real);
        assertThrows(IOException.class, () -> new FlowKeyStore(base()).save(FLOW, RSA.getPrivate(), PASSWORD));
        try (Stream<Path> s = Files.list(real)) {
            assertEquals(0, s.count());
        }
    }

    @Test
    void baseDirThatIsAFileIsRejected() throws Exception {
        Files.writeString(base(), "x");
        assertThrows(IOException.class, () -> new FlowKeyStore(base()).save(FLOW, RSA.getPrivate(), PASSWORD));
    }

    @Test
    void symlinkedKeyFileIsNotRead() throws Exception {
        FlowKeyStore store = new FlowKeyStore(base());
        store.save(FLOW, RSA.getPrivate(), PASSWORD);
        Path keyFile = base().resolve(FLOW).resolve("key.bin");
        Path moved = Files.move(keyFile, tmp.resolve("moved.bin"));
        Files.createSymbolicLink(keyFile, moved);
        assertThrows(IOException.class, () -> store.load(FLOW, PASSWORD));
    }

    @Test
    void keysOlderThanThirtyDaysArePurgedOnSave() throws Exception {
        FlowKeyStore store = new FlowKeyStore(base());
        String old = "aaaaaaaa-0000-0000-0000-000000000001";
        String fresh = "aaaaaaaa-0000-0000-0000-000000000002";
        store.save(old, RSA.getPrivate(), PASSWORD);
        store.save(fresh, RSA.getPrivate(), PASSWORD);
        Files.setLastModifiedTime(base().resolve(old), FileTime.from(Instant.now().minus(Duration.ofDays(31))));
        Files.setLastModifiedTime(base().resolve(fresh), FileTime.from(Instant.now().minus(Duration.ofDays(29))));

        store.save(FLOW, RSA.getPrivate(), PASSWORD);

        assertFalse(Files.exists(base().resolve(old), LinkOption.NOFOLLOW_LINKS), "expired key must be purged");
        assertTrue(Files.exists(base().resolve(fresh)), "key younger than 30 days must stay");
        assertTrue(Files.exists(base().resolve(FLOW)));
    }

    @Test
    void expiredKeysArePurgedOnDeleteToo() throws Exception {
        FlowKeyStore store = new FlowKeyStore(base());
        String old = "aaaaaaaa-0000-0000-0000-000000000003";
        store.save(old, RSA.getPrivate(), PASSWORD);
        store.save(FLOW, RSA.getPrivate(), PASSWORD);
        Files.setLastModifiedTime(base().resolve(old), FileTime.from(Instant.now().minus(Duration.ofDays(40))));
        store.delete(FLOW);
        assertFalse(Files.exists(base().resolve(FLOW)));
        assertFalse(Files.exists(base().resolve(old)), "expired key must be purged after delete");
    }

    @Test
    void existsReportsStoredKeysOnly() throws Exception {
        FlowKeyStore store = new FlowKeyStore(base());
        assertFalse(store.exists(FLOW), "store directory does not even exist");
        store.save(FLOW, RSA.getPrivate(), PASSWORD);
        assertTrue(store.exists(FLOW));
        assertFalse(store.exists("11111111-2222-3333-4444-555555555555"));
        store.delete(FLOW);
        assertFalse(store.exists(FLOW));
    }

    @Test
    void existsIgnoresSymlinkedKeyFile() throws Exception {
        FlowKeyStore store = new FlowKeyStore(base());
        store.save(FLOW, RSA.getPrivate(), PASSWORD);
        Path keyFile = base().resolve(FLOW).resolve("key.bin");
        Path moved = Files.move(keyFile, tmp.resolve("moved.bin"));
        Files.createSymbolicLink(keyFile, moved);
        assertFalse(store.exists(FLOW));
    }

    @ParameterizedTest
    @NullSource
    @ValueSource(strings = { "../../etc", "abc/../../x", "short" })
    void existsRejectsInvalidFlowIds(String flowId) {
        assertThrows(IllegalArgumentException.class, () -> new FlowKeyStore(base()).exists(flowId));
    }

    private static boolean posix() {
        return FileSystems.getDefault().supportedFileAttributeViews().contains("posix");
    }

    private static int indexOf(byte[] haystack, byte[] needle) {
        outer: for (int i = 0; i <= haystack.length - needle.length; i++) {
            for (int j = 0; j < needle.length; j++) {
                if (haystack[i + j] != needle[j]) {
                    continue outer;
                }
            }
            return i;
        }
        return -1;
    }
}
