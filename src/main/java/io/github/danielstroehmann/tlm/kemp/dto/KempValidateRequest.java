package io.github.danielstroehmann.tlm.kemp.dto;

import com.digicert.tlm.workflows.automation.dto.ValidateCertificateRequest;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.databind.JsonNode;

import lombok.Data;
import lombok.EqualsAndHashCode;

/** {@code validateCertificate} payload; the SDK DTO itself carries no fields. */
@Data
@EqualsAndHashCode(callSuper = true)
@JsonIgnoreProperties(ignoreUnknown = true)
public class KempValidateRequest extends ValidateCertificateRequest<JsonNode> {
    private String certificateSerialNumber;
    private String ipAddress;
    private String port;
    private String virtualServerName;
}
