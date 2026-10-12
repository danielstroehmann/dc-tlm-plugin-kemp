package io.github.danielstroehmann.tlm.kemp;

import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.function.BiFunction;

import com.digicert.tlm.workflows.WorkflowExecutionException;

import io.github.danielstroehmann.tlm.kemp.client.Capabilities;
import io.github.danielstroehmann.tlm.kemp.client.KempApiException;
import io.github.danielstroehmann.tlm.kemp.client.KempClient;
import io.github.danielstroehmann.tlm.kemp.loadmaster.ServedCertificate;
import io.github.danielstroehmann.tlm.kemp.loadmaster.Snapshot;
import io.github.danielstroehmann.tlm.kemp.loadmaster.Target;
import io.github.danielstroehmann.tlm.kemp.loadmaster.VirtualService;
import io.github.danielstroehmann.tlm.kemp.pki.Pem;
import lombok.extern.slf4j.Slf4j;

/**
 * Installs issued certificates on the LoadMaster and reads back what a target actually serves.
 * <p>
 * Every install first plans all steps and checks all permissions, and only then writes, so a refusal never leaves
 * a half-changed LoadMaster behind.
 */
@Slf4j
final class CertificateService {

    private static final DateTimeFormatter SUFFIX = DateTimeFormatter.ofPattern("yyyyMMddHHmmss");

    private final KempClient client;
    private final Map<String, Optional<X509Certificate>> certCache = new LinkedHashMap<>();

    /** Reads the certificate a service presents in the TLS handshake; replaceable in tests. */
    BiFunction<String, Integer, Optional<X509Certificate>> servedCertificate =
            (host, port) -> ServedCertificate.fetch(host, port, ServedCertificate.DEFAULT_TIMEOUT);

    CertificateService(KempClient client) {
        this.client = client;
    }

    /** Issued certificate and the CA certificates that provably issued it, without duplicates. */
    record Chain(X509Certificate leaf, List<X509Certificate> intermediates) {
    }

    /**
     * Picks the leaf (the certificate matching the flow's private key) and the CA path above it from an
     * unordered certificate package. CA certificates that did not sign the path are dropped, so a tampered package
     * cannot plant intermediates in the LoadMaster's shared store.
     */
    static Chain buildChain(List<X509Certificate> certificates, PrivateKey key)
            throws GeneralSecurityException, WorkflowExecutionException {
        Map<String, X509Certificate> unique = new LinkedHashMap<>();
        for (X509Certificate c : certificates) {
            unique.putIfAbsent(Pem.sha256(c), c);
        }
        X509Certificate leaf = unique.values().stream().filter(c -> Pem.keyMatches(key, c)).findFirst()
                .orElseThrow(() -> new WorkflowExecutionException(
                        "Issued certificate does not match the private key generated for this flow"));
        validateLeaf(leaf);
        List<X509Certificate> path = new ArrayList<>();
        X509Certificate current = leaf;
        while (true) {
            X509Certificate child = current;
            Optional<X509Certificate> issuer = unique.values().stream()
                    .filter(c -> c != child && Pem.isCa(c) && !path.contains(c) && Pem.issuedBy(child, c))
                    .findFirst();
            if (issuer.isEmpty() || Pem.isSelfSigned(issuer.get())) {
                break; // roots are never uploaded — clients must already trust them
            }
            path.add(issuer.get());
            current = issuer.get();
        }
        return new Chain(leaf, Collections.unmodifiableList(path));
    }

    /** Refuses certificates that cannot serve TLS: CA certificates, expired or not yet valid, wrong key usage. */
    static void validateLeaf(X509Certificate leaf) throws WorkflowExecutionException {
        if (Pem.isCa(leaf)) {
            throw new WorkflowExecutionException("Issued certificate is a CA certificate");
        }
        try {
            leaf.checkValidity();
        } catch (java.security.cert.CertificateException e) {
            throw new WorkflowExecutionException("Issued certificate is not currently valid: " + e.getMessage());
        }
        try {
            List<String> eku = leaf.getExtendedKeyUsage();
            if (eku != null && !eku.contains("1.3.6.1.5.5.7.3.1") && !eku.contains("2.5.29.37.0")) {
                throw new WorkflowExecutionException("Issued certificate is not valid for TLS server authentication");
            }
        } catch (java.security.cert.CertificateParsingException e) {
            throw new WorkflowExecutionException("Issued certificate has an unreadable extended key usage");
        }
    }

    /**
     * True if the certificate is already in place on the target (retry of a completed install). For the web UI
     * a missing assignment is repaired if the certificate exists under the expected identifier.
     *
     * @param key the flow's private key if it still exists (it is deleted after a successful install)
     */
    boolean alreadyInstalled(Snapshot snapshot, Capabilities caps, Target target, List<X509Certificate> certificates,
            Optional<PrivateKey> key) throws KempApiException, GeneralSecurityException {
        // While the flow key exists, only the certificate issued for it counts — a package that merely contains
        // the currently bound (public) certificate must not end the flow.
        Set<String> fingerprints = new HashSet<>();
        for (X509Certificate c : certificates) {
            if (!Pem.isCa(c) && (key.isEmpty() || Pem.keyMatches(key.get(), c))) {
                fingerprints.add(Pem.sha256(c));
            }
        }
        if (fingerprints.isEmpty()) {
            return false;
        }
        for (String id : boundIdentifiers(snapshot, target)) {
            Optional<X509Certificate> bound = read(id);
            if (bound.isPresent() && fingerprints.contains(Pem.sha256(bound.get()))) {
                log.info("Certificate is already installed as '{}' - nothing to do", id);
                return true;
            }
        }
        if (target instanceof Target.Management && snapshot.adminCertificate() == null && caps.adminCert()) {
            // A previous run uploaded the certificate but failed to assign it to the web UI.
            for (String id : client.listCertificates()) {
                Optional<X509Certificate> cert = read(id);
                if (cert.isPresent() && fingerprints.contains(Pem.sha256(cert.get()))) {
                    client.setAdminCertificate(id);
                    log.info("Repaired web UI assignment to already uploaded certificate '{}'", id);
                    return true;
                }
            }
        }
        return false;
    }

    /**
     * @param thumbprint certificate being replaced (TLM's {@code currentCertificateThumbprint}), may be empty
     */
    void install(Snapshot snapshot, Capabilities caps, Target target, PrivateKey key, Chain chain, String thumbprint)
            throws KempApiException, GeneralSecurityException, WorkflowExecutionException {
        String pem = Pem.toPem(chain.leaf()) + Pem.toPem(key);
        List<X509Certificate> missingCas = missingIntermediates(chain.intermediates());

        // ---- plan and check (no writes) ----
        require(caps.certWrite(), "Certificate Creation");
        if (!missingCas.isEmpty()) {
            require(caps.intermediateWrite(), "Intermediate Certificates");
        }
        boolean hasThumbprint = thumbprint != null && !thumbprint.isBlank();

        if (target instanceof Target.Management) {
            if (!caps.adminCert()) {
                throw new WorkflowExecutionException(
                        "Managing the LoadMaster web UI certificate requires the Kemp permission 'All Permissions'");
            }
            if (!snapshot.adminCertificateManageable()) {
                throw new WorkflowExecutionException("The web UI certificate '" + snapshot.adminCertificate()
                        + "' is managed by the LoadMaster's ACME client; assign a regular certificate first");
            }
            String current = snapshot.adminCertificate();
            boolean renew = current != null && hasThumbprint && matches(current, thumbprint);
            if (hasThumbprint && !renew) {
                throw notFound(thumbprint, "the web UI");
            }
            uploadIntermediates(missingCas);
            String id = renew ? current : newIdentifier(chain.leaf());
            client.addCertificate(id, pem, renew);
            // Replacing the active web UI certificate drops the assignment (verified on 7.2.63): always set it again.
            client.setAdminCertificate(id);
            log.info("Web UI certificate is now '{}'", id);
            return;
        }

        VirtualService vs = ((Target.Vs) target).virtualService();
        Set<String> acme = new HashSet<>(vs.certificates());
        acme.retainAll(snapshot.acmeCertificates());
        if (!acme.isEmpty()) {
            throw new WorkflowExecutionException("Virtual service " + vs.endpoint()
                    + " uses certificates managed by the LoadMaster's ACME client: " + acme);
        }

        String renewId = null;
        if (hasThumbprint) {
            for (String id : vs.certificates()) {
                if (matches(id, thumbprint)) {
                    renewId = id;
                    break;
                }
            }
            if (renewId == null && !vs.factoryCertificate()) {
                throw notFound(thumbprint, vs.endpoint());
            }
            if (renewId == null) {
                require(caps.vsWrite(), "Virtual Services");
                confirmFactoryCertificate(vs, thumbprint);
            }
        }
        if (renewId != null) {
            boolean isAdmin = renewId.equals(snapshot.adminCertificate());
            if (isAdmin && !caps.adminCert()) {
                throw new WorkflowExecutionException("Certificate '" + renewId + "' is also the web UI certificate;"
                        + " replacing it would drop that assignment, which needs the Kemp permission 'All Permissions'");
            }
            uploadIntermediates(missingCas);
            // Renewal in place: every virtual service referencing this identifier picks up the new certificate.
            client.addCertificate(renewId, pem, true);
            if (isAdmin) {
                client.setAdminCertificate(renewId);
            }
            log.info("Replaced certificate '{}' used by {}", renewId, vs.endpoint());
            return;
        }

        if (vs.factoryCertificate()) {
            // TLM renews the built-in default certificate reported by the inventory: that is a first install.
            log.info("Replacing Kemp's built-in certificate on {} with a first certificate", vs.endpoint());
        }
        // First install: supersede a certificate for the same host names at its position (non-SNI clients get the
        // first entry), otherwise add the certificate as an additional SNI entry.
        require(caps.vsWrite(), "Virtual Services");
        uploadIntermediates(missingCas);
        String newId = newIdentifier(chain.leaf());
        client.addCertificate(newId, pem, false);
        boolean assignmentSent = false;
        try {
            List<String> current = VirtualService.from(client.showVirtualService(vs.index())).certificates();
            List<String> assigned = withNewCertificate(current, newId, chain.leaf());
            assignmentSent = true;
            client.setVirtualServiceCertificates(vs.index(), assigned);
            log.info("Assigned new certificate '{}' to {}: {}", newId, vs.endpoint(), assigned);
        } catch (KempApiException e) {
            rollback(vs.index(), newId, assignmentSent);
            throw e;
        }
    }

    /**
     * The built-in certificate is not readable through the API, so TLM's thumbprint is compared with the certificate
     * the service presents right now. Refused before any write if it differs or cannot be read.
     */
    private void confirmFactoryCertificate(VirtualService vs, String thumbprint)
            throws GeneralSecurityException, WorkflowExecutionException {
        Optional<X509Certificate> presented = servedCertificate.apply(vs.address(), vs.port());
        if (presented.isEmpty()) {
            throw new WorkflowExecutionException("Certificate " + thumbprint + " to be replaced on " + vs.endpoint()
                    + " could not be confirmed: the service's certificate is not readable from the sensor");
        }
        if (!Pem.matchesThumbprint(presented.get(), thumbprint)) {
            // Kemp may have regenerated its built-in certificate since the last inventory (e.g. after a reboot).
            throw new WorkflowExecutionException("Certificate " + thumbprint + " is no longer presented by "
                    + vs.endpoint() + "; refresh the configuration in TLM and renew again. Nothing was changed.");
        }
    }

    /**
     * Kemp serves the first matching entry of the list (verified on 7.2.63). Entries whose names the new certificate
     * covers completely and that use the same key type are dropped (an RSA/ECDSA pair keeps its other half); the new
     * certificate takes the position of the first entry that it covers or overlaps, so no remaining readable entry
     * can serve its names first. Unrelated certificates are kept; without any overlap the new one is appended.
     */
    private List<String> withNewCertificate(List<String> current, String newId, X509Certificate leaf)
            throws KempApiException {
        Set<String> newNames = Pem.dnsNames(leaf);
        List<String> result = new ArrayList<>();
        int insertAt = -1;
        for (String id : current) {
            Optional<X509Certificate> existing = read(id);
            Set<String> oldNames = existing.isPresent() ? Pem.dnsNames(existing.get()) : Set.of();
            boolean covered = existing.isPresent() && covers(newNames, oldNames)
                    && Pem.keyFamily(existing.get()).equals(Pem.keyFamily(leaf));
            if (insertAt < 0 && (covered || overlaps(newNames, oldNames))) {
                insertAt = result.size();
            }
            if (covered) {
                log.info("New certificate supersedes '{}' (covers all its host names) on this virtual service", id);
            } else {
                result.add(id);
            }
        }
        if (insertAt < 0) {
            result.add(newId);
        } else {
            result.add(insertAt, newId);
        }
        return result;
    }

    /** True if any name of one set is matched by a name of the other, exactly or by a single-label wildcard. */
    static boolean overlaps(Set<String> a, Set<String> b) {
        for (String x : a) {
            for (String y : b) {
                if (nameMatches(x, y) || nameMatches(y, x)) {
                    return true;
                }
            }
        }
        return false;
    }

    private static boolean nameMatches(String pattern, String host) {
        if (pattern.equals(host)) {
            return true;
        }
        return pattern.startsWith("*.") && !host.startsWith("*.") && host.indexOf('.') > 0
                && host.substring(host.indexOf('.')).equals(pattern.substring(1));
    }

    /** True if every old name is matched by a new name (exactly or by a single-label wildcard). */
    static boolean covers(Set<String> newNames, Set<String> oldNames) {
        if (oldNames.isEmpty()) {
            return false;
        }
        for (String old : oldNames) {
            boolean matched = newNames.contains(old) || newNames.stream().anyMatch(n -> n.startsWith("*.")
                    && !old.startsWith("*.") && old.indexOf('.') > 0
                    && old.substring(old.indexOf('.')).equals(n.substring(1)));
            if (!matched) {
                return false;
            }
        }
        return true;
    }

    /**
     * Removes the uploaded certificate. If the assignment was sent, it may have gone through despite the error
     * (e.g. timeout after modvs), so the service is re-read first and an assigned certificate is kept.
     */
    private void rollback(String vsIndex, String identifier, boolean assignmentSent) {
        try {
            if (assignmentSent
                    && VirtualService.from(client.showVirtualService(vsIndex)).certificates().contains(identifier)) {
                log.warn("Certificate '{}' is assigned despite the error; not rolled back", identifier);
                return;
            }
            client.deleteCertificate(identifier);
            log.info("Rolled back: removed unassigned certificate '{}'", identifier);
        } catch (KempApiException e) {
            log.error("Could not remove unassigned certificate '{}' after a failed assignment: {}",
                    identifier, e.getMessage());
        }
    }

    /** CA certificates the LoadMaster does not know yet; compared by fingerprint. */
    private List<X509Certificate> missingIntermediates(List<X509Certificate> cas)
            throws KempApiException, GeneralSecurityException {
        if (cas.isEmpty()) {
            return List.of();
        }
        Set<String> known = new HashSet<>();
        for (String id : client.listIntermediates()) {
            try {
                known.add(Pem.sha256(Pem.parseCertificate(client.readIntermediate(id))));
            } catch (KempApiException | GeneralSecurityException e) {
                if (e instanceof KempClient.KempTransportException) {
                    throw (KempApiException) e;
                }
                log.warn("Intermediate '{}' could not be read: {}", id, e.getMessage());
            }
        }
        List<X509Certificate> missing = new ArrayList<>();
        for (X509Certificate ca : cas) {
            if (!known.contains(Pem.sha256(ca))) {
                missing.add(ca);
            }
        }
        return missing;
    }

    private void uploadIntermediates(List<X509Certificate> cas) throws KempApiException, GeneralSecurityException {
        for (X509Certificate ca : cas) {
            String id = "tlm-ica-" + Pem.sha256(ca).substring(0, 16).toLowerCase(Locale.ROOT);
            client.addIntermediate(id, Pem.toPem(ca));
            log.info("Added intermediate certificate '{}' ({})", id, ca.getSubjectX500Principal().getName());
        }
    }

    /** Returns the PEM of the certificate bound to {@code target} whose serial matches. */
    Optional<String> findBound(Snapshot snapshot, Target target, String serialHex) throws KempApiException {
        for (String id : boundIdentifiers(snapshot, target)) {
            Optional<X509Certificate> cert = read(id);
            if (cert.isPresent() && Pem.matchesSerial(cert.get(), serialHex)) {
                try {
                    return Optional.of(Pem.toPem(cert.get()));
                } catch (GeneralSecurityException e) {
                    log.warn("Certificate '{}' could not be encoded: {}", id, e.getMessage());
                }
            }
        }
        return Optional.empty();
    }

    private static List<String> boundIdentifiers(Snapshot snapshot, Target target) {
        if (target instanceof Target.Vs vs) {
            return vs.virtualService().certificates();
        }
        return snapshot.adminCertificate() == null ? List.of() : List.of(snapshot.adminCertificate());
    }

    /** Reads and parses a certificate once; unreadable certificates are skipped, transport errors propagate. */
    private Optional<X509Certificate> read(String identifier) throws KempApiException {
        if (certCache.containsKey(identifier)) {
            return certCache.get(identifier);
        }
        Optional<X509Certificate> result;
        try {
            result = Optional.of(Pem.parseCertificate(client.readCertificate(identifier)));
        } catch (KempClient.KempTransportException e) {
            throw e;
        } catch (KempApiException | GeneralSecurityException e) {
            log.warn("Certificate '{}' could not be read: {}", identifier, e.getMessage());
            result = Optional.empty();
        }
        certCache.put(identifier, result);
        return result;
    }

    private boolean matches(String identifier, String thumbprint) throws KempApiException, GeneralSecurityException {
        Optional<X509Certificate> cert = read(identifier);
        return cert.isPresent() && Pem.matchesThumbprint(cert.get(), thumbprint);
    }

    /** {@code tlm-<CN>}, made unique with a UTC timestamp if the identifier already exists. */
    String newIdentifier(X509Certificate leaf) throws KempApiException {
        String cn = Optional.ofNullable(Pem.commonName(leaf)).orElse("certificate");
        String base = "tlm-" + cn.replace("*", "wildcard").replaceAll("[^A-Za-z0-9._-]", "-");
        if (base.length() > 200) {
            base = base.substring(0, 200);
        }
        Set<String> existing = new HashSet<>();
        client.listCertificates().forEach(n -> existing.add(n.toLowerCase(Locale.ROOT)));
        if (!existing.contains(base.toLowerCase(Locale.ROOT))) {
            return base;
        }
        return base + "-" + ZonedDateTime.now(ZoneOffset.UTC).format(SUFFIX);
    }

    private static void require(boolean granted, String permission) throws WorkflowExecutionException {
        if (!granted) {
            throw new WorkflowExecutionException("The API key lacks the Kemp permission '" + permission + "'");
        }
    }

    private static WorkflowExecutionException notFound(String thumbprint, String where) {
        return new WorkflowExecutionException("The certificate to replace (thumbprint " + thumbprint
                + ") is not in use on " + where + "; nothing was changed");
    }
}
