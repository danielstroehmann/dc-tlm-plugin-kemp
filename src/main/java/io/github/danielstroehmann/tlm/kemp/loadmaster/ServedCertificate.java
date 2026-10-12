package io.github.danielstroehmann.tlm.kemp.loadmaster;

import java.net.InetSocketAddress;
import java.net.Socket;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicReference;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509ExtendedTrustManager;

import lombok.extern.slf4j.Slf4j;

/**
 * Reads the certificate a virtual service presents in the TLS handshake. Needed for Kemp's built-in default
 * certificate (issued by Kemp's own CA), which the API does not expose ({@code readcert} answers "Unknown certificate").
 * <p>
 * Only a handshake is performed (no application data is sent) and the result is used for inventory and to confirm
 * TLM's thumbprint, so the peer is deliberately not verified. The trust manager lives in a per-call SSLContext and
 * never affects other connections.
 */
@Slf4j
public final class ServedCertificate {

    public static final Duration DEFAULT_TIMEOUT = Duration.ofSeconds(3);

    private ServedCertificate() {
    }

    public static Optional<X509Certificate> fetch(String host, int port, Duration timeout) {
        AtomicReference<X509Certificate> presented = new AtomicReference<>();
        try {
            SSLContext context = SSLContext.getInstance("TLS");
            context.init(null, new TrustManager[] { new CapturingTrustManager(presented) }, null);
            try (SSLSocket socket = (SSLSocket) context.getSocketFactory().createSocket()) {
                socket.connect(new InetSocketAddress(host, port), (int) timeout.toMillis());
                socket.setSoTimeout((int) timeout.toMillis());
                socket.startHandshake();
            }
        } catch (Exception e) {
            // The certificate may still have been captured, e.g. when the service then demands a client certificate.
            if (presented.get() == null) {
                log.info("Presented certificate of {}:{} not readable: {}", host, port, e.getMessage());
            }
        }
        return Optional.ofNullable(presented.get());
    }

    /**
     * Captures the server certificate and accepts it. Extended variant so the JDK applies no hostname or algorithm
     * constraints on top: a weak factory certificate must still be readable.
     */
    private static final class CapturingTrustManager extends X509ExtendedTrustManager {
        private final AtomicReference<X509Certificate> presented;

        CapturingTrustManager(AtomicReference<X509Certificate> presented) {
            this.presented = presented;
        }

        private void capture(X509Certificate[] chain) {
            if (chain != null && chain.length > 0) {
                presented.set(chain[0]);
            }
        }

        @Override
        public void checkServerTrusted(X509Certificate[] chain, String authType) {
            capture(chain);
        }

        @Override
        public void checkServerTrusted(X509Certificate[] chain, String authType, Socket socket) {
            capture(chain);
        }

        @Override
        public void checkServerTrusted(X509Certificate[] chain, String authType, SSLEngine engine) {
            capture(chain);
        }

        @Override
        public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
            throw new CertificateException("not a server");
        }

        @Override
        public void checkClientTrusted(X509Certificate[] chain, String authType, Socket socket)
                throws CertificateException {
            throw new CertificateException("not a server");
        }

        @Override
        public void checkClientTrusted(X509Certificate[] chain, String authType, SSLEngine engine)
                throws CertificateException {
            throw new CertificateException("not a server");
        }

        @Override
        public X509Certificate[] getAcceptedIssuers() {
            return new X509Certificate[0];
        }
    }
}
