package io.github.danielstroehmann.tlm.kemp.pki;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.StringWriter;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collection;
import java.util.HexFormat;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.TreeSet;

import javax.naming.InvalidNameException;
import javax.naming.ldap.LdapName;
import javax.naming.ldap.Rdn;

import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemWriter;

/** PEM/X.509 helpers based on the JDK. */
public final class Pem {

    private Pem() {
    }

    /** Parses one or more certificates from PEM text or base64-encoded DER. */
    public static List<X509Certificate> parseCertificates(String text) throws CertificateException {
        if (text == null || text.isBlank()) {
            return List.of();
        }
        byte[] bytes = text.contains("-----BEGIN")
                ? text.getBytes(StandardCharsets.US_ASCII)
                : Base64.getMimeDecoder().decode(text.trim());
        List<X509Certificate> result = new ArrayList<>();
        for (Certificate c : CertificateFactory.getInstance("X.509")
                .generateCertificates(new ByteArrayInputStream(bytes))) {
            result.add((X509Certificate) c);
        }
        return result;
    }

    /** Parses DER or PEM bytes (single certificate or concatenation). */
    public static List<X509Certificate> parseCertificatesDer(byte[] bytes) throws CertificateException {
        List<X509Certificate> result = new ArrayList<>();
        for (Certificate c : CertificateFactory.getInstance("X.509")
                .generateCertificates(new ByteArrayInputStream(bytes))) {
            result.add((X509Certificate) c);
        }
        return result;
    }

    public static X509Certificate parseCertificate(String text) throws CertificateException {
        List<X509Certificate> certs = parseCertificates(text);
        if (certs.isEmpty()) {
            throw new CertificateException("No certificate found");
        }
        return certs.get(0);
    }

    public static String toPem(X509Certificate cert) throws CertificateException {
        return block("CERTIFICATE", cert.getEncoded());
    }

    /** PKCS#8 ("PRIVATE KEY"), the format Kemp's certificate import accepts for RSA and EC. */
    public static String toPem(PrivateKey key) {
        return block("PRIVATE KEY", key.getEncoded());
    }

    static String block(String type, byte[] der) {
        StringWriter out = new StringWriter();
        try (PemWriter writer = new PemWriter(out)) {
            writer.writeObject(new PemObject(type, der));
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
        return out.toString();
    }

    /** Upper-case hex SHA-256 over the DER encoding (the format TLM uses for thumbprints). */
    public static String sha256(X509Certificate cert) throws GeneralSecurityException {
        return digest("SHA-256", cert);
    }

    public static String sha1(X509Certificate cert) throws GeneralSecurityException {
        return digest("SHA-1", cert);
    }

    private static String digest(String algorithm, X509Certificate cert) throws GeneralSecurityException {
        return HexFormat.of().withUpperCase().formatHex(MessageDigest.getInstance(algorithm).digest(cert.getEncoded()));
    }

    /** True if {@code thumbprint} (SHA-256 or SHA-1, any case, optional colons) identifies {@code cert}. */
    public static boolean matchesThumbprint(X509Certificate cert, String thumbprint) throws GeneralSecurityException {
        if (thumbprint == null || thumbprint.isBlank()) {
            return false;
        }
        String normalized = thumbprint.replace(":", "").trim().toUpperCase(Locale.ROOT);
        return normalized.length() == 40 ? normalized.equals(sha1(cert)) : normalized.equals(sha256(cert));
    }

    /** Compares hex serial numbers ignoring case, colons and leading zeros. */
    public static boolean matchesSerial(X509Certificate cert, String serialHex) {
        if (serialHex == null || serialHex.isBlank()) {
            return false;
        }
        String normalized = serialHex.replace(":", "").trim().replaceFirst("^0+(?=.)", "").toLowerCase(Locale.ROOT);
        return cert.getSerialNumber().toString(16).equals(normalized);
    }

    public static String commonName(X509Certificate cert) {
        try {
            for (Rdn rdn : new LdapName(cert.getSubjectX500Principal().getName()).getRdns()) {
                if (rdn.getType().equalsIgnoreCase("CN")) {
                    return rdn.getValue().toString();
                }
            }
        } catch (InvalidNameException e) {
            // fall through
        }
        return null;
    }

    public static boolean isSelfSigned(X509Certificate cert) {
        return cert.getSubjectX500Principal().equals(cert.getIssuerX500Principal());
    }

    /** Proves that {@code key} belongs to {@code cert} by signing and verifying a challenge. */
    public static boolean keyMatches(PrivateKey key, X509Certificate cert) {
        PublicKey pub = cert.getPublicKey();
        String algorithm = family(key.getAlgorithm());
        if (!algorithm.equals(family(pub.getAlgorithm()))) {
            return false;
        }
        String signatureAlgorithm = "EC".equals(algorithm) ? "SHA256withECDSA" : "SHA256withRSA";
        try {
            byte[] challenge = "kemp-tlm-plugin-key-check".getBytes(StandardCharsets.US_ASCII);
            Signature signer = Signature.getInstance(signatureAlgorithm);
            signer.initSign(key);
            signer.update(challenge);
            byte[] signature = signer.sign();
            Signature verifier = Signature.getInstance(signatureAlgorithm);
            verifier.initVerify(pub);
            verifier.update(challenge);
            return verifier.verify(signature);
        } catch (GeneralSecurityException e) {
            return false;
        }
    }

    /** Key family of the certificate's public key ("RSA", "EC", ...). */
    public static String keyFamily(X509Certificate cert) {
        return family(cert.getPublicKey().getAlgorithm());
    }

    /** BouncyCastle names EC keys "ECDSA", the JDK "EC". */
    private static String family(String algorithm) {
        return "ECDSA".equalsIgnoreCase(algorithm) ? "EC" : algorithm.toUpperCase(Locale.ROOT);
    }

    /** True if {@code cert} is a CA certificate (basicConstraints CA=true). */
    public static boolean isCa(X509Certificate cert) {
        return cert.getBasicConstraints() >= 0;
    }

    /** True if {@code cert} was signed by {@code issuer}. */
    public static boolean issuedBy(X509Certificate cert, X509Certificate issuer) {
        if (!cert.getIssuerX500Principal().equals(issuer.getSubjectX500Principal())) {
            return false;
        }
        try {
            cert.verify(issuer.getPublicKey());
            return true;
        } catch (GeneralSecurityException e) {
            return false;
        }
    }

    /** DNS names a certificate is valid for: SAN dNSName entries, or the CN if there are none. */
    public static Set<String> dnsNames(X509Certificate cert) {
        Set<String> names = new TreeSet<>();
        try {
            Collection<List<?>> sans = cert.getSubjectAlternativeNames();
            if (sans != null) {
                for (List<?> san : sans) {
                    if (Integer.valueOf(2).equals(san.get(0))) {
                        names.add(san.get(1).toString().toLowerCase(Locale.ROOT));
                    }
                }
            }
        } catch (CertificateParsingException e) {
            // treat as no SAN
        }
        String cn = commonName(cert);
        if (names.isEmpty() && cn != null) {
            names.add(cn.toLowerCase(Locale.ROOT));
        }
        return names;
    }
}
