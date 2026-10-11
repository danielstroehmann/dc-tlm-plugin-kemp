package io.github.danielstroehmann.tlm.kemp.client;

import java.util.ArrayList;
import java.util.List;

/**
 * What the configured API key may do on the LoadMaster, as detected by {@link KempClient#probeCapabilities()}.
 *
 * @param certWrite         upload/replace certificates ("Certificate Creation")
 * @param intermediateWrite upload intermediate certificates ("Intermediate Certificates")
 * @param vsWrite           assign certificates to virtual services ("Virtual Services")
 * @param adminCert         set the web UI certificate — on Kemp only possible with "All Permissions"
 */
public record Capabilities(boolean certWrite, boolean intermediateWrite, boolean vsWrite, boolean adminCert) {

    /** Kemp permission names (as shown in the web UI) that are missing for virtual service automation. */
    public List<String> missingStandardPermissions() {
        List<String> missing = new ArrayList<>();
        if (!certWrite) {
            missing.add("Certificate Creation");
        }
        if (!intermediateWrite) {
            missing.add("Intermediate Certificates");
        }
        if (!vsWrite) {
            missing.add("Virtual Services");
        }
        return missing;
    }
}
