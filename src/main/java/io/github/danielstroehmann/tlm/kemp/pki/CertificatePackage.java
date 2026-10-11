package io.github.danielstroehmann.tlm.kemp.pki;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

/**
 * Downloads and unpacks the certificate package behind TLM's {@code certificateLink}.
 * <p>
 * Used instead of the SDK's {@code DownloadCertificateUtil}, which disables TLS verification and reads unbounded
 * data. Here TLS is verified against the JVM trust store, redirects never downgrade from https to http, and the
 * download and every archive entry are size-limited.
 */
public final class CertificatePackage {

    static final int MAX_DOWNLOAD_BYTES = 5 * 1024 * 1024;
    static final int MAX_ENTRY_BYTES = 1024 * 1024;
    static final int MAX_ENTRIES = 64;

    private CertificatePackage() {
    }

    public static List<X509Certificate> download(String link) throws IOException, CertificateException {
        URI uri = URI.create(link);
        if (!"https".equalsIgnoreCase(uri.getScheme())) {
            throw new IOException("certificateLink must use https");
        }
        HttpClient http = HttpClient.newBuilder()
                .followRedirects(HttpClient.Redirect.NORMAL) // NORMAL never follows https -> http
                .connectTimeout(Duration.ofSeconds(20))
                .build();
        HttpRequest request = HttpRequest.newBuilder(uri).timeout(Duration.ofSeconds(60)).GET().build();
        HttpResponse<InputStream> response;
        try {
            response = http.send(request, HttpResponse.BodyHandlers.ofInputStream());
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IOException("Certificate download interrupted", e);
        }
        byte[] body;
        try (InputStream in = response.body()) {
            if (response.statusCode() / 100 != 2) {
                throw new IOException("Certificate download failed with HTTP " + response.statusCode());
            }
            body = readLimited(in, MAX_DOWNLOAD_BYTES, "certificate package");
        }
        return parse(body);
    }

    /** A ZIP of certificate files (.cer/.crt/.pem/.p7b), or a single certificate/PKCS#7 file. */
    static List<X509Certificate> parse(byte[] body) throws IOException, CertificateException {
        if (body.length < 4 || body[0] != 'P' || body[1] != 'K') {
            return Pem.parseCertificatesDer(body);
        }
        List<X509Certificate> result = new ArrayList<>();
        int entries = 0;
        try (ZipInputStream zip = new ZipInputStream(new ByteArrayInputStream(body))) {
            ZipEntry entry;
            while ((entry = zip.getNextEntry()) != null) {
                if (++entries > MAX_ENTRIES) {
                    throw new IOException("Certificate package has too many entries");
                }
                String name = entry.getName().toLowerCase(Locale.ROOT);
                if (entry.isDirectory() || !(name.endsWith(".cer") || name.endsWith(".crt")
                        || name.endsWith(".pem") || name.endsWith(".p7b"))) {
                    continue;
                }
                result.addAll(Pem.parseCertificatesDer(readLimited(zip, MAX_ENTRY_BYTES, entry.getName())));
            }
        }
        return result;
    }

    private static byte[] readLimited(InputStream in, int limit, String what) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        byte[] buffer = new byte[8192];
        int total = 0;
        int n;
        while ((n = in.read(buffer)) != -1) {
            total += n;
            if (total > limit) {
                throw new IOException("The " + what + " exceeds " + limit + " bytes");
            }
            out.write(buffer, 0, n);
        }
        return out.toByteArray();
    }
}
