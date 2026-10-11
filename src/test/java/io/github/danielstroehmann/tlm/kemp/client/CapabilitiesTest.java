package io.github.danielstroehmann.tlm.kemp.client;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.util.List;

import org.junit.jupiter.api.Test;

class CapabilitiesTest {

    @Test
    void nothingMissingWithAllStandardPermissions() {
        assertEquals(List.of(), new Capabilities(true, true, true, false).missingStandardPermissions());
    }

    @Test
    void namesEveryMissingPermissionInKempTerms() {
        assertEquals(List.of("Certificate Creation", "Intermediate Certificates", "Virtual Services"),
                new Capabilities(false, false, false, true).missingStandardPermissions());
        assertEquals(List.of("Intermediate Certificates"), new Capabilities(true, false, true, true).missingStandardPermissions());
        assertEquals(List.of("Certificate Creation"), new Capabilities(false, true, true, false).missingStandardPermissions());
        assertEquals(List.of("Virtual Services"), new Capabilities(true, true, false, false).missingStandardPermissions());
    }
}
