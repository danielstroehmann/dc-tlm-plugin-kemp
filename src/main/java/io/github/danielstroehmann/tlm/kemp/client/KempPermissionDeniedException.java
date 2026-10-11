package io.github.danielstroehmann.tlm.kemp.client;

/** The API key lacks the LoadMaster permission for a command ({@code "message":"Permission denied"}). */
public class KempPermissionDeniedException extends KempApiException {

    public KempPermissionDeniedException(String command) {
        super("LoadMaster denied permission for API command '" + command + "'");
    }
}
