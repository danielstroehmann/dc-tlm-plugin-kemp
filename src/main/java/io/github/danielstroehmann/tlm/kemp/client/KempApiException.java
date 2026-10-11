package io.github.danielstroehmann.tlm.kemp.client;

/** A LoadMaster API call failed (transport error, HTTP error page or {@code "status":"fail"}). */
public class KempApiException extends Exception {

    public KempApiException(String message) {
        super(message);
    }

    public KempApiException(String message, Throwable cause) {
        super(message, cause);
    }
}
