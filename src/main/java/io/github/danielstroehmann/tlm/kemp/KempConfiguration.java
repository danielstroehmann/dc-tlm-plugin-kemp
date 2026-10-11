package io.github.danielstroehmann.tlm.kemp;

import lombok.Data;
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
}
