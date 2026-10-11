package io.github.danielstroehmann.tlm.kemp.pki;

import java.io.IOException;
import java.io.StringWriter;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.security.spec.ECGenParameterSpec;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x500.style.IETFUtils;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.ExtensionsGenerator;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;

import com.digicert.tlm.crypto.CryptoPolicy;

/** Generates the key pair and PKCS#10 CSR for a TLM automation request. */
public final class CsrGenerator {

    private static final Pattern DIGEST_BITS = Pattern.compile("(256|384|512)");
    /** RFC 1123 labels (1–63 chars, no leading/trailing hyphen), optional leading wildcard label. */
    private static final Pattern DNS_NAME = Pattern.compile(
            "^(\\*\\.)?([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?\\.)+[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?$");
    /** A numeric top-level label means an IP literal, which must not become a dNSName SAN. */
    private static final Pattern NUMERIC_TLD = Pattern.compile("\\.[0-9]+$");

    static {
        // Routes all crypto through the SDK policy (standard BC or BC-FIPS, whichever is on the classpath).
        Security.addProvider(CryptoPolicy.get().provider());
    }

    public record Result(KeyPair keyPair, String csrPem) {
    }

    private CsrGenerator() {
    }

    /**
     * @param subjectDn          RFC 4514 DN; NUL-separated RDNs (seen in TLM requests) are accepted too
     * @param dnsNames           comma-separated SAN DNS names, may be empty
     * @param keyAlgorithm       {@code RSA} or {@code EC}/{@code ECDSA}
     * @param keySize            RSA bits (min. 2048) or EC curve size ({@code 256}, {@code 384}, {@code 521}, {@code P-256} ...)
     * @param signatureAlgorithm {@code sha256}/{@code sha384}/{@code sha512} (or a JCA name containing the digest size)
     */
    public static Result generate(String subjectDn, String dnsNames, String keyAlgorithm, String keySize,
            String signatureAlgorithm) throws GeneralSecurityException {
        if (subjectDn == null || subjectDn.isBlank()) {
            throw new IllegalArgumentException("subjectDn is required");
        }
        X500Name subject = new X500Name(BCStyle.INSTANCE, subjectDn.replace('\u0000', ','));
        boolean ec = isEc(keyAlgorithm);
        KeyPair keyPair = generateKeyPair(ec, keySize);

        JcaPKCS10CertificationRequestBuilder builder = new JcaPKCS10CertificationRequestBuilder(subject, keyPair.getPublic());
        List<String> sans = subjectAlternativeNames(subject, dnsNames);
        if (!sans.isEmpty()) {
            try {
                GeneralName[] names = sans.stream().map(n -> new GeneralName(GeneralName.dNSName, n)).toArray(GeneralName[]::new);
                ExtensionsGenerator extensions = new ExtensionsGenerator();
                extensions.addExtension(Extension.subjectAlternativeName, false, new GeneralNames(names));
                builder.addAttribute(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest, extensions.generate());
            } catch (IOException e) {
                throw new GeneralSecurityException("Cannot encode subjectAltName", e);
            }
        }

        String jcaSignature = "SHA" + digestBits(signatureAlgorithm) + "with" + (ec ? "ECDSA" : "RSA");
        try {
            PKCS10CertificationRequest csr = builder.build(new JcaContentSignerBuilder(jcaSignature)
                    .setProvider(CryptoPolicy.get().provider()).build(keyPair.getPrivate()));
            StringWriter out = new StringWriter();
            try (JcaPEMWriter writer = new JcaPEMWriter(out)) {
                writer.writeObject(csr);
            }
            return new Result(keyPair, out.toString());
        } catch (OperatorCreationException | IOException e) {
            throw new GeneralSecurityException("Cannot build CSR", e);
        }
    }

    private static boolean isEc(String keyAlgorithm) {
        String a = keyAlgorithm == null ? "RSA" : keyAlgorithm.trim().toUpperCase(Locale.ROOT);
        return switch (a) {
            case "RSA", "" -> false;
            case "EC", "ECC", "ECDSA" -> true;
            default -> throw new IllegalArgumentException("Unsupported key algorithm: " + keyAlgorithm);
        };
    }

    private static KeyPair generateKeyPair(boolean ec, String keySize) throws GeneralSecurityException {
        String size = keySize == null ? "" : keySize.trim().toUpperCase(Locale.ROOT);
        if (ec) {
            String curve = switch (size.replaceAll("[^0-9]", "")) {
                case "", "256" -> "secp256r1";
                case "384" -> "secp384r1";
                case "521" -> "secp521r1";
                default -> throw new IllegalArgumentException("Unsupported EC key size: " + keySize);
            };
            KeyPairGenerator generator = CryptoPolicy.get().keyPairGenerator("EC");
            generator.initialize(new ECGenParameterSpec(curve), CryptoPolicy.get().secureRandom());
            return generator.generateKeyPair();
        }
        int bits;
        try {
            bits = size.isEmpty() ? 2048 : Integer.parseInt(size);
        } catch (NumberFormatException e) {
            throw new IllegalArgumentException("Invalid RSA key size: " + keySize);
        }
        if (bits < 2048 || bits > 8192) {
            throw new IllegalArgumentException("RSA key size must be between 2048 and 8192 bits: " + bits);
        }
        KeyPairGenerator generator = CryptoPolicy.get().keyPairGenerator("RSA");
        generator.initialize(bits, CryptoPolicy.get().secureRandom());
        return generator.generateKeyPair();
    }

    private static String digestBits(String signatureAlgorithm) {
        if (signatureAlgorithm == null || signatureAlgorithm.isBlank()) {
            return "256";
        }
        Matcher m = DIGEST_BITS.matcher(signatureAlgorithm);
        if (!m.find()) {
            throw new IllegalArgumentException("Unsupported signature algorithm: " + signatureAlgorithm);
        }
        return m.group(1);
    }

    static boolean isDnsName(String name) {
        return name.length() <= 253 && DNS_NAME.matcher(name).matches() && !NUMERIC_TLD.matcher(name).find();
    }

    /** SAN list from the request; the CN is added when it is a DNS name, as clients ignore the CN today. */
    static List<String> subjectAlternativeNames(X500Name subject, String dnsNames) {
        Set<String> names = new LinkedHashSet<>();
        for (RDN rdn : subject.getRDNs(BCStyle.CN)) {
            String cn = IETFUtils.valueToString(rdn.getFirst().getValue());
            if (isDnsName(cn)) {
                names.add(cn.toLowerCase(Locale.ROOT));
            }
        }
        if (dnsNames != null) {
            for (String n : dnsNames.split(",")) {
                String name = n.trim();
                if (name.isEmpty()) {
                    continue;
                }
                if (!isDnsName(name)) {
                    throw new IllegalArgumentException("Invalid DNS name in dnsNames: " + name);
                }
                names.add(name.toLowerCase(Locale.ROOT));
            }
        }
        return new ArrayList<>(names);
    }
}
