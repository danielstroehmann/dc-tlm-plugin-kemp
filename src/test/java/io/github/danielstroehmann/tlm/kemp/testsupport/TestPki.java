package io.github.danielstroehmann.tlm.kemp.testsupport;

import java.io.StringReader;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.Date;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequest;

/** Generates throw-away test keys and certificates in memory (nothing is read from or written to disk). */
public final class TestPki {

    static {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    private static final SecureRandom RANDOM = new SecureRandom();

    private TestPki() {
    }

    public static KeyPair rsa(int bits) {
        try {
            KeyPairGenerator g = KeyPairGenerator.getInstance("RSA");
            g.initialize(bits, RANDOM);
            return g.generateKeyPair();
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    public static KeyPair ec(String curve) {
        try {
            KeyPairGenerator g = KeyPairGenerator.getInstance("EC");
            g.initialize(new ECGenParameterSpec(curve), RANDOM);
            return g.generateKeyPair();
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    /** A root CA and an issuing (intermediate) CA below it. */
    public static final class Ca {
        public final KeyPair rootKeys = rsa(2048);
        public final X509Certificate root;
        public final KeyPair issuingKeys = rsa(2048);
        public final X509Certificate issuing;

        public Ca(String name) {
            root = build(new X500Name("CN=" + name + " Root CA,O=Example"), new X500Name("CN=" + name + " Root CA,O=Example"),
                    rootKeys.getPublic(), rootKeys.getPrivate(), BigInteger.ONE, true);
            issuing = build(new X500Name("CN=" + name + " Root CA,O=Example"),
                    new X500Name("CN=" + name + " Issuing CA,O=Example"), issuingKeys.getPublic(), rootKeys.getPrivate(),
                    BigInteger.TWO, true);
        }

        /** Leaf for {@code publicKey}, issued by the issuing CA. */
        public X509Certificate issue(PublicKey publicKey, String cn, BigInteger serial, String... dnsNames) {
            return buildLeaf(issuing, issuingKeys.getPrivate(), publicKey, cn, serial, dnsNames);
        }

        /** Leaf with explicit validity and extended key usages (none given = no EKU extension). */
        public X509Certificate issueCustom(PublicKey publicKey, String cn, Instant notBefore, Instant notAfter,
                boolean ca, org.bouncycastle.asn1.x509.KeyPurposeId... eku) {
            try {
                X509v3CertificateBuilder b = new JcaX509v3CertificateBuilder(
                        X500Name.getInstance(issuing.getSubjectX500Principal().getEncoded()),
                        new BigInteger(64, RANDOM), Date.from(notBefore), Date.from(notAfter), new X500Name("CN=" + cn),
                        publicKey);
                b.addExtension(Extension.basicConstraints, true, new BasicConstraints(ca));
                if (eku.length > 0) {
                    b.addExtension(Extension.extendedKeyUsage, false, new org.bouncycastle.asn1.x509.ExtendedKeyUsage(eku));
                }
                return sign(b, issuingKeys.getPrivate());
            } catch (Exception e) {
                throw new IllegalStateException(e);
            }
        }

        /** A second-level issuing CA below {@link #issuing} (root → issuing → sub). */
        public Issuer subordinate(String cn) {
            KeyPair keys = rsa(2048);
            X509Certificate cert = build(X500Name.getInstance(issuing.getSubjectX500Principal().getEncoded()),
                    new X500Name("CN=" + cn + ",O=Example"), keys.getPublic(), issuingKeys.getPrivate(),
                    BigInteger.valueOf(3), true);
            return new Issuer(cert, keys);
        }

        /** Signs a PKCS#10 CSR (PEM) and returns the leaf certificate. */
        public X509Certificate issueFromCsr(String csrPem, BigInteger serial) {
            try (PEMParser parser = new PEMParser(new StringReader(csrPem))) {
                PKCS10CertificationRequest csr = (PKCS10CertificationRequest) parser.readObject();
                PublicKey pub = new JcaPKCS10CertificationRequest(csr).setProvider(BouncyCastleProvider.PROVIDER_NAME)
                        .getPublicKey();
                String cn = csr.getSubject().getRDNs(org.bouncycastle.asn1.x500.style.BCStyle.CN)[0].getFirst().getValue()
                        .toString();
                return issue(pub, cn, serial, cn);
            } catch (Exception e) {
                throw new IllegalStateException(e);
            }
        }
    }

    /** Any CA certificate with its key pair, able to issue leaves. */
    public record Issuer(X509Certificate cert, KeyPair keys) {
        public X509Certificate issue(PublicKey publicKey, String cn, BigInteger serial, String... dnsNames) {
            return buildLeaf(cert, keys.getPrivate(), publicKey, cn, serial, dnsNames);
        }
    }

    public static X509Certificate selfSigned(KeyPair keys, String cn) {
        X500Name name = new X500Name("CN=" + cn);
        return build(name, name, keys.getPublic(), keys.getPrivate(), new BigInteger(64, RANDOM), false);
    }

    private static X509Certificate buildLeaf(X509Certificate issuer, PrivateKey issuerKey, PublicKey publicKey, String cn,
            BigInteger serial, String... dnsNames) {
        try {
            Instant now = Instant.now();
            X509v3CertificateBuilder b = new JcaX509v3CertificateBuilder(
                    X500Name.getInstance(issuer.getSubjectX500Principal().getEncoded()), serial,
                    Date.from(now.minus(1, ChronoUnit.DAYS)), Date.from(now.plus(90, ChronoUnit.DAYS)),
                    new X500Name("CN=" + cn), publicKey);
            b.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));
            if (dnsNames.length > 0) {
                GeneralName[] names = new GeneralName[dnsNames.length];
                for (int i = 0; i < dnsNames.length; i++) {
                    names[i] = new GeneralName(GeneralName.dNSName, dnsNames[i]);
                }
                b.addExtension(Extension.subjectAlternativeName, false, new GeneralNames(names));
            }
            return sign(b, issuerKey);
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    private static X509Certificate build(X500Name issuer, X500Name subject, PublicKey publicKey, PrivateKey signer,
            BigInteger serial, boolean ca) {
        try {
            Instant now = Instant.now();
            X509v3CertificateBuilder b = new JcaX509v3CertificateBuilder(issuer, serial,
                    Date.from(now.minus(1, ChronoUnit.DAYS)), Date.from(now.plus(365, ChronoUnit.DAYS)), subject, publicKey);
            b.addExtension(Extension.basicConstraints, true, new BasicConstraints(ca));
            return sign(b, signer);
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    private static X509Certificate sign(X509v3CertificateBuilder b, PrivateKey signer) throws Exception {
        String alg = "RSA".equals(signer.getAlgorithm()) ? "SHA256withRSA" : "SHA256withECDSA";
        return new JcaX509CertificateConverter().setProvider(BouncyCastleProvider.PROVIDER_NAME)
                .getCertificate(b.build(new JcaContentSignerBuilder(alg).setProvider(BouncyCastleProvider.PROVIDER_NAME)
                        .build(signer)));
    }

    public static String pem(X509Certificate... certs) {
        StringBuilder sb = new StringBuilder();
        for (X509Certificate c : certs) {
            try {
                sb.append("-----BEGIN CERTIFICATE-----\n")
                        .append(Base64.getMimeEncoder(64, "\n".getBytes()).encodeToString(c.getEncoded()))
                        .append("\n-----END CERTIFICATE-----\n");
            } catch (Exception e) {
                throw new IllegalStateException(e);
            }
        }
        return sb.toString();
    }
}
