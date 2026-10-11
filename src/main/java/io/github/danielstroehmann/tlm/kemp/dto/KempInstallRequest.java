package io.github.danielstroehmann.tlm.kemp.dto;

import com.digicert.tlm.workflows.automation.dto.InstallCertificateRequest;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.databind.JsonNode;

import lombok.Data;
import lombok.EqualsAndHashCode;

/** {@code installCertificate} payload incl. the endpoint fields TLM sends but the SDK DTO lacks. */
@Data
@EqualsAndHashCode(callSuper = true)
@JsonIgnoreProperties(ignoreUnknown = true)
public class KempInstallRequest extends InstallCertificateRequest<JsonNode> {
    private String ipAddress;
    private String port;
    private String virtualServerName;
}
