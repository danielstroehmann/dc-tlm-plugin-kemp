package io.github.danielstroehmann.tlm.kemp.testsupport;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;

import org.slf4j.event.Level;

import com.digicert.tlm.plugin.PluginLogger;

/**
 * Captures plugin log output. The active SLF4J provider is the SDK's {@code PluginLogger} (it wins over slf4j-simple),
 * which resolves {@code System.out} (INFO/DEBUG) and {@code System.err} (WARN/ERROR) on every call. Both streams are
 * captured and still echoed; the level is raised to TRACE while capturing so debug output is checked too.
 */
public final class LogCapture implements AutoCloseable {

    private final PrintStream originalOut = System.out;
    private final PrintStream originalErr = System.err;
    private final Level originalLevel = PluginLogger.getLevel();
    private final ByteArrayOutputStream buffer = new ByteArrayOutputStream();

    public LogCapture() {
        System.setOut(new PrintStream(new TeeStream(buffer, originalOut), true, StandardCharsets.UTF_8));
        System.setErr(new PrintStream(new TeeStream(buffer, originalErr), true, StandardCharsets.UTF_8));
        PluginLogger.setLevel(Level.TRACE);
    }

    public String text() {
        System.out.flush();
        System.err.flush();
        synchronized (buffer) {
            return buffer.toString(StandardCharsets.UTF_8);
        }
    }

    @Override
    public void close() {
        System.out.flush();
        System.err.flush();
        System.setOut(originalOut);
        System.setErr(originalErr);
        PluginLogger.setLevel(originalLevel);
    }

    private static final class TeeStream extends OutputStream {
        private final ByteArrayOutputStream capture;
        private final OutputStream echo;

        TeeStream(ByteArrayOutputStream capture, OutputStream echo) {
            this.capture = capture;
            this.echo = echo;
        }

        @Override
        public void write(int c) throws IOException {
            synchronized (capture) {
                capture.write(c);
            }
            echo.write(c);
        }

        @Override
        public void write(byte[] buf, int off, int len) throws IOException {
            synchronized (capture) {
                capture.write(buf, off, len);
            }
            echo.write(buf, off, len);
        }

        @Override
        public void flush() throws IOException {
            echo.flush();
        }
    }
}
