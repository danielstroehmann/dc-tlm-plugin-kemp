package io.github.danielstroehmann.tlm.kemp.loadmaster;

/** The endpoint a TLM request refers to. */
public sealed interface Target {

    /** The LoadMaster's own web UI / API certificate (case H). */
    record Management() implements Target {
    }

    record Vs(VirtualService virtualService) implements Target {
    }
}
