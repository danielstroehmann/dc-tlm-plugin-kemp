package io.github.danielstroehmann.tlm.kemp;

import java.util.Set;
import java.util.TreeSet;

import com.fasterxml.jackson.annotation.JsonAnySetter;

import lombok.AccessLevel;
import lombok.Data;
import lombok.Getter;
import lombok.Setter;
import lombok.ToString;

/**
 * Connector settings entered in TLM. Field names must match the {@code config_attributes.*} names in
 * {@code configuration.json}, otherwise the value silently arrives as {@code null}.
 */
@Data
public class KempConfiguration {

    /** Hostname or IP of the LoadMaster web UI / API (shared address for HA pairs). */
    private String managementHost;

    /** Web UI / API port, usually 443 (8443 on cloud images). Kept as string: TLM sends form input. */
    private String managementPort;

    @ToString.Exclude
    private String apiKey;

    /** Names (never values) of settings TLM sent that this class does not map — for diagnosing field naming. */
    @Getter(AccessLevel.NONE)
    @Setter(AccessLevel.NONE)
    @ToString.Exclude
    private final Set<String> unmappedSettings = new TreeSet<>();

    @JsonAnySetter
    void unmapped(String name, Object ignored) {
        unmappedSettings.add(name);
    }

    public Set<String> unmappedSettingNames() {
        return Set.copyOf(unmappedSettings);
    }
}
