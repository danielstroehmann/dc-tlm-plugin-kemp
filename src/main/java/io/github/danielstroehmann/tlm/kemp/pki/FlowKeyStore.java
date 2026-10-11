package io.github.danielstroehmann.tlm.kemp.pki;

import java.io.IOException;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.attribute.FileTime;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.nio.file.attribute.UserPrincipal;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.time.Duration;
import java.time.Instant;
import java.util.Comparator;
import java.util.Set;
import java.util.regex.Pattern;
import java.util.stream.Stream;

import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.openssl.PEMException;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;

import com.digicert.tlm.crypto.CryptoPolicy;

import lombok.extern.slf4j.Slf4j;

/**
 * Keeps the private key between {@code generateCsr} and {@code installCertificate}, which run as separate
 * processes on the sensor. The key is stored encrypted with the SDK's PBE key wrapping, using the connector's
 * API key as password (never written to disk), in an owner-only directory, and deleted after installation.
 */
@Slf4j
public final class FlowKeyStore {

    /** TLM flow IDs are UUIDs; anything else is rejected to rule out path traversal. */
    private static final Pattern FLOW_ID = Pattern.compile("^[A-Za-z0-9-]{8,64}$");
    private static final Duration MAX_AGE = Duration.ofDays(30);
    private static final String KEY_FILE = "key.bin";

    private final Path baseDir;

    public FlowKeyStore(Path baseDir) {
        this.baseDir = baseDir;
    }

    public static FlowKeyStore defaultStore() {
        return new FlowKeyStore(Path.of(System.getProperty("java.io.tmpdir"), "kemp-loadmaster-plugin"));
    }

    public void save(String flowId, PrivateKey key, char[] password) throws IOException, GeneralSecurityException {
        Path dir = flowDir(flowId);
        createPrivateDirectory(baseDir);
        purgeExpired();
        createPrivateDirectory(dir);
        byte[] wrapped = CryptoPolicy.get().pbeWrapPrivateKey(key.getEncoded(), password);
        Path file = dir.resolve(KEY_FILE);
        Files.deleteIfExists(file);
        if (isPosix()) {
            Files.createFile(file, PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------")));
        }
        Files.write(file, wrapped);
    }

    public boolean exists(String flowId) {
        return Files.isRegularFile(flowDir(flowId).resolve(KEY_FILE), LinkOption.NOFOLLOW_LINKS);
    }

    public PrivateKey load(String flowId, char[] password) throws IOException, GeneralSecurityException {
        Path file = flowDir(flowId).resolve(KEY_FILE);
        if (!Files.isRegularFile(file, LinkOption.NOFOLLOW_LINKS)) {
            throw new IOException("No private key stored for flow " + flowId
                    + " — generateCsr must run on the same sensor before installCertificate");
        }
        byte[] pkcs8;
        try {
            pkcs8 = CryptoPolicy.get().pbeUnwrapPrivateKey(Files.readAllBytes(file), password);
        } catch (GeneralSecurityException e) {
            throw new GeneralSecurityException("Stored private key for flow " + flowId
                    + " cannot be decrypted — was the connector's API key changed since generateCsr?", e);
        }
        try {
            return new JcaPEMKeyConverter().getPrivateKey(PrivateKeyInfo.getInstance(pkcs8));
        } catch (PEMException e) {
            throw new GeneralSecurityException("Stored private key is unreadable", e);
        }
    }

    public void delete(String flowId) throws IOException {
        deleteRecursively(flowDir(flowId));
        purgeExpired();
    }

    private Path flowDir(String flowId) {
        if (flowId == null || !FLOW_ID.matcher(flowId).matches()) {
            throw new IllegalArgumentException("Invalid flowId");
        }
        return baseDir.resolve(flowId);
    }

    /** Keys of flows that never reached installCertificate must not linger on the sensor (30 days). */
    private void purgeExpired() {
        if (!Files.isDirectory(baseDir, LinkOption.NOFOLLOW_LINKS)) {
            return;
        }
        try {
            createPrivateDirectory(baseDir); // never purge inside a directory owned by someone else
        } catch (IOException e) {
            log.warn("Skipping key purge: {}", e.getMessage());
            return;
        }
        Instant limit = Instant.now().minus(MAX_AGE);
        try (Stream<Path> dirs = Files.list(baseDir)) {
            dirs.filter(d -> isOlderThan(d, limit)).forEach(d -> {
                try {
                    deleteRecursively(d);
                    log.info("Removed expired key directory {}", d.getFileName());
                } catch (IOException e) {
                    log.warn("Cannot remove expired key directory {}: {}", d.getFileName(), e.getMessage());
                }
            });
        } catch (IOException e) {
            log.warn("Cannot scan key directory: {}", e.getMessage());
        }
    }

    private static boolean isOlderThan(Path p, Instant limit) {
        try {
            FileTime t = Files.getLastModifiedTime(p, LinkOption.NOFOLLOW_LINKS);
            return t.toInstant().isBefore(limit);
        } catch (IOException e) {
            return false;
        }
    }

    /**
     * Creates an owner-only directory. An existing directory must be a real directory owned by the current
     * user — a pre-created directory or symlink in a shared temp folder could otherwise expose the key file.
     */
    private static void createPrivateDirectory(Path dir) throws IOException {
        if (Files.exists(dir, LinkOption.NOFOLLOW_LINKS)) {
            if (!Files.isDirectory(dir, LinkOption.NOFOLLOW_LINKS)) {
                throw new IOException("Key directory path is not a directory: " + dir);
            }
            if (isPosix()) {
                if (!currentUser().equals(Files.getOwner(dir, LinkOption.NOFOLLOW_LINKS))) {
                    throw new IOException("Key directory is owned by another user: " + dir);
                }
                Files.setPosixFilePermissions(dir, PosixFilePermissions.fromString("rwx------"));
            }
            return;
        }
        if (isPosix()) {
            Set<PosixFilePermission> perms = PosixFilePermissions.fromString("rwx------");
            Files.createDirectory(dir, PosixFilePermissions.asFileAttribute(perms));
        } else {
            Files.createDirectory(dir);
        }
    }

    /** Owner of a freshly created file — works where the user name cannot be looked up (containers, services). */
    private static UserPrincipal currentUser() throws IOException {
        Path probe = Files.createTempFile("kemp-plugin-owner", ".tmp");
        try {
            return Files.getOwner(probe);
        } finally {
            Files.deleteIfExists(probe);
        }
    }

    private static void deleteRecursively(Path dir) throws IOException {
        if (!Files.exists(dir, LinkOption.NOFOLLOW_LINKS)) {
            return;
        }
        try (Stream<Path> walk = Files.walk(dir)) {
            for (Path p : walk.sorted(Comparator.reverseOrder()).toList()) {
                Files.delete(p);
            }
        }
    }

    private static boolean isPosix() {
        return FileSystems.getDefault().supportedFileAttributeViews().contains("posix");
    }
}
