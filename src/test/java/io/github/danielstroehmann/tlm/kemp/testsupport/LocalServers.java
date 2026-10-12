package io.github.danielstroehmann.tlm.kemp.testsupport;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLSocket;

/** Throw-away loopback servers for handshake tests (127.0.0.1 only, daemon threads, closed by the test). */
public final class LocalServers {

    private LocalServers() {
    }

    /** TLS server presenting {@link #certificate}; completes the handshake, then closes the connection. */
    public static final class Tls implements AutoCloseable {
        public final X509Certificate certificate;
        private final SSLServerSocket socket;

        public Tls(String cn) throws Exception {
            this(cn, false);
        }

        /** @param needClientAuth the server demands a client certificate (the handshake then fails for the client) */
        public Tls(String cn, boolean needClientAuth) throws Exception {
            this(TestPki.rsa(2048), null, cn, needClientAuth);
        }

        /** Presents {@code cert} (for {@code keys}); a self-signed certificate is generated when {@code cert} is null. */
        public Tls(KeyPair keys, X509Certificate cert, String cn, boolean needClientAuth) throws Exception {
            certificate = cert != null ? cert : TestPki.selfSigned(keys, cn);
            char[] pass = "test-only".toCharArray();
            KeyStore ks = KeyStore.getInstance("PKCS12");
            ks.load(null, null);
            ks.setKeyEntry("server", keys.getPrivate(), pass, new X509Certificate[] { certificate });
            KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            kmf.init(ks, pass);
            SSLContext ctx = SSLContext.getInstance("TLS");
            ctx.init(kmf.getKeyManagers(), null, null);
            socket = (SSLServerSocket) ctx.getServerSocketFactory().createServerSocket(0, 50, InetAddress.getLoopbackAddress());
            socket.setNeedClientAuth(needClientAuth);
            Thread t = new Thread(() -> {
                while (!socket.isClosed()) {
                    try (SSLSocket s = (SSLSocket) socket.accept()) {
                        s.setSoTimeout(5000);
                        s.startHandshake();
                    } catch (IOException e) {
                        // client aborted or server closed
                    }
                }
            }, "test-tls-server");
            t.setDaemon(true);
            t.start();
        }

        public int port() {
            return socket.getLocalPort();
        }

        @Override
        public void close() throws IOException {
            socket.close();
        }
    }

    /** Plain TCP server that accepts and then stays silent (or sends a plain-text line). */
    public static final class Plain implements AutoCloseable {
        private final ServerSocket socket;
        private final List<Socket> open = new ArrayList<>();

        public Plain(String greeting) throws IOException {
            socket = new ServerSocket(0, 50, InetAddress.getLoopbackAddress());
            Thread t = new Thread(() -> {
                while (!socket.isClosed()) {
                    try {
                        Socket s = socket.accept();
                        synchronized (open) {
                            open.add(s);
                        }
                        if (greeting != null) {
                            OutputStream out = s.getOutputStream();
                            out.write(greeting.getBytes(StandardCharsets.US_ASCII));
                            out.flush();
                        }
                    } catch (IOException e) {
                        // closed
                    }
                }
            }, "test-plain-server");
            t.setDaemon(true);
            t.start();
        }

        public int port() {
            return socket.getLocalPort();
        }

        @Override
        public void close() throws IOException {
            socket.close();
            synchronized (open) {
                for (Socket s : open) {
                    s.close();
                }
            }
        }
    }

    public static int closedPort() throws IOException {
        try (ServerSocket s = new ServerSocket(0, 1, InetAddress.getLoopbackAddress())) {
            return s.getLocalPort();
        }
    }
}
