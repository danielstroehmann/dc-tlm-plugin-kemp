package io.github.danielstroehmann.tlm.kemp;

import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Optional;
import java.util.regex.Pattern;

import com.digicert.tlm.SdkContext;
import com.digicert.tlm.plugin.PluginError;
import com.digicert.tlm.plugin.PluginUtils;
import com.digicert.tlm.plugin.Response;
import com.digicert.tlm.plugin.WorkflowEntryPoint;
import com.digicert.tlm.plugin.model.PluginConfiguration;
import com.digicert.tlm.workflows.WorkflowExecutionException;
import com.digicert.tlm.workflows.automation.AbstractAutomationWorkflow;
import com.digicert.tlm.workflows.automation.dto.GenerateCsrRequest;
import com.digicert.tlm.workflows.automation.dto.GenerateCsrResponse;
import com.digicert.tlm.workflows.automation.dto.InstallCertificateResponse;
import com.digicert.tlm.workflows.automation.dto.TestConnectionResponse;
import com.digicert.tlm.workflows.automation.dto.ValidateCertificateResponse;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import io.github.danielstroehmann.tlm.kemp.client.Capabilities;
import io.github.danielstroehmann.tlm.kemp.client.KempClient;
import io.github.danielstroehmann.tlm.kemp.dto.KempInstallRequest;
import io.github.danielstroehmann.tlm.kemp.dto.KempValidateRequest;
import io.github.danielstroehmann.tlm.kemp.loadmaster.Snapshot;
import io.github.danielstroehmann.tlm.kemp.loadmaster.Target;
import io.github.danielstroehmann.tlm.kemp.pki.CertificatePackage;
import io.github.danielstroehmann.tlm.kemp.pki.CsrGenerator;
import io.github.danielstroehmann.tlm.kemp.pki.FlowKeyStore;
import io.github.danielstroehmann.tlm.kemp.pki.Pem;
import lombok.extern.slf4j.Slf4j;

/**
 * TLM automation plugin for Kemp/Progress LoadMaster: inventory of TLS virtual services (and, with
 * "All Permissions", the web UI certificate), key/CSR generation on the sensor and certificate installation.
 */
@Slf4j
@WorkflowEntryPoint(name = KempLoadMasterPlugin.NAME)
@SuppressWarnings("unchecked")
public class KempLoadMasterPlugin extends AbstractAutomationWorkflow {

    public static final String NAME = "KempLoadMasterPlugin";

    /** PluginUtils.convertWrappedObject only handles generic DTOs; the extended request classes are not generic. */
    private static final ObjectMapper REQUEST_MAPPER = new ObjectMapper()
            .configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);

    /** Hostname, IPv4 address or bracketed IPv6 address — nothing that could alter the request URL. */
    private static final Pattern HOST = Pattern.compile("^([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)(\\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$|^\\[[0-9A-Fa-f:.]+\\]$");

    private final KempConfiguration config;
    private final FlowKeyStore keyStore;

    public KempLoadMasterPlugin(SdkContext context, PluginConfiguration<KempConfiguration> configuration) {
        super(context);
        this.config = configuration.getExtendedConfig();
        this.keyStore = FlowKeyStore.defaultStore();
    }

    KempLoadMasterPlugin(KempConfiguration config, FlowKeyStore keyStore) {
        super(new SdkContext());
        this.config = config;
        this.keyStore = keyStore;
    }

    /** Overridable in tests to point at a mock LoadMaster. */
    KempClient openClient() throws WorkflowExecutionException {
        return KempClient.connect(host(), port(), apiKey());
    }

    String host() throws WorkflowExecutionException {
        String host = config == null || config.getManagementHost() == null ? "" : config.getManagementHost().trim();
        if (host.isEmpty() || host.length() > 253 || !HOST.matcher(host).matches()) {
            throw new WorkflowExecutionException("Invalid or missing LoadMaster host — use a hostname, an IPv4 address"
                    + " or a bracketed IPv6 address, without protocol or port");
        }
        return host;
    }

    private int port() throws WorkflowExecutionException {
        String value = config.getManagementPort();
        try {
            int port = value == null || value.isBlank() ? 443 : Integer.parseInt(value.trim());
            if (port >= 1 && port <= 65535) {
                return port;
            }
        } catch (NumberFormatException e) {
            // fall through
        }
        throw new WorkflowExecutionException("Invalid management port: " + value);
    }

    private String apiKey() throws WorkflowExecutionException {
        if (config == null || config.getApiKey() == null || config.getApiKey().isBlank()) {
            throw new WorkflowExecutionException("Connector configuration incomplete: API key is required");
        }
        return config.getApiKey();
    }

    @Override
    public Response<JsonNode> testConnection(JsonNode request) throws WorkflowExecutionException {
        try (KempClient client = openClient()) {
            String version = client.get("version");
            Capabilities caps = client.probeCapabilities();
            log.info("Connected to LoadMaster {} — capabilities {}", version, caps);
            TestConnectionResponse<JsonNode> response = new TestConnectionResponse<>();
            List<String> missing = caps.missingStandardPermissions();
            response.setActive(missing.isEmpty());
            if (!missing.isEmpty()) {
                response.setErrors(List.of(new PluginError("failed",
                        "Connected to LoadMaster " + version + ", but the API key lacks the Kemp permission(s): "
                                + String.join(", ", missing))));
            }
            return response;
        } catch (WorkflowExecutionException e) {
            throw e;
        } catch (Exception e) {
            throw new WorkflowExecutionException("testConnection failed: " + e.getMessage(), e);
        }
    }

    @Override
    public Response<JsonNode> refreshConfiguration(JsonNode request) throws WorkflowExecutionException {
        try (KempClient client = openClient()) {
            Snapshot snapshot = Snapshot.load(client, host());
            // Only the web UI capability matters here; fewer probes mean less noise in the LoadMaster audit log.
            return new Inventory(client).build(snapshot, client.probeAdminCertificate());
        } catch (WorkflowExecutionException e) {
            throw e;
        } catch (Exception e) {
            throw new WorkflowExecutionException("refreshConfiguration failed: " + e.getMessage(), e);
        }
    }

    @Override
    public Response<JsonNode> generateCsr(JsonNode request) throws WorkflowExecutionException {
        try {
            GenerateCsrRequest<JsonNode> r = PluginUtils.convertWrappedObject(request, GenerateCsrRequest.class);
            log.info("generateCsr flow={} subject='{}' dnsNames='{}' key={} {} sig={}", r.getFlowId(), r.getSubjectDn(),
                    r.getDnsNames(), r.getKeyAlgorithm(), r.getKeySize(), r.getSignatureAlgorithm());
            String apiKey = apiKey();
            CsrGenerator.Result result = CsrGenerator.generate(r.getSubjectDn(), r.getDnsNames(), r.getKeyAlgorithm(),
                    r.getKeySize(), r.getSignatureAlgorithm());
            keyStore.save(r.getFlowId(), result.keyPair().getPrivate(), apiKey.toCharArray());
            GenerateCsrResponse<JsonNode> response = new GenerateCsrResponse<>();
            response.setCsr(result.csrPem());
            return response;
        } catch (WorkflowExecutionException e) {
            throw e;
        } catch (Exception e) {
            throw new WorkflowExecutionException("generateCsr failed: " + e.getMessage(), e);
        }
    }

    @Override
    public Response<JsonNode> installCertificate(JsonNode request) throws WorkflowExecutionException {
        KempInstallRequest r;
        try {
            r = REQUEST_MAPPER.convertValue(request, KempInstallRequest.class);
        } catch (Exception e) {
            throw new WorkflowExecutionException("installCertificate: invalid request: " + e.getMessage(), e);
        }
        log.info("installCertificate flow={} target={}:{} virtualServerName='{}' replacing={}", r.getFlowId(),
                r.getIpAddress(), r.getPort(), r.getVirtualServerName(), r.getCurrentCertificateThumbprint());
        try (KempClient client = openClient()) {
            Snapshot snapshot = Snapshot.load(client, host());
            Target target = snapshot.resolve(r.getIpAddress(), r.getPort(), r.getVirtualServerName())
                    .orElseThrow(() -> new WorkflowExecutionException("No manageable endpoint for " + r.getIpAddress()
                            + ":" + r.getPort() + " (" + r.getVirtualServerName() + ") — SSL must be enabled on the virtual service"));
            List<X509Certificate> certificates = obtainCertificates(r);
            Capabilities caps = client.probeCapabilities();
            CertificateService service = new CertificateService(client);

            // A retry after a completed install must succeed without changes (the key is gone by then).
            Optional<PrivateKey> key = keyStore.exists(r.getFlowId())
                    ? Optional.of(keyStore.load(r.getFlowId(), apiKey().toCharArray()))
                    : Optional.empty();
            if (!service.alreadyInstalled(snapshot, caps, target, certificates, key)) {
                PrivateKey privateKey = key.orElseThrow(() -> new WorkflowExecutionException("No private key stored for flow "
                        + r.getFlowId() + " — generateCsr must run on the same sensor before installCertificate"));
                service.install(snapshot, caps, target, privateKey, CertificateService.buildChain(certificates, privateKey),
                        r.getCurrentCertificateThumbprint());
            }
        } catch (WorkflowExecutionException e) {
            throw e;
        } catch (Exception e) {
            throw new WorkflowExecutionException("installCertificate failed: " + e.getMessage(), e);
        }
        deleteKeyQuietly(r.getFlowId());
        return new InstallCertificateResponse<>();
    }

    @Override
    public Response<JsonNode> validateCertificate(JsonNode request) throws WorkflowExecutionException {
        try (KempClient client = openClient()) {
            KempValidateRequest r = REQUEST_MAPPER.convertValue(request, KempValidateRequest.class);
            Snapshot snapshot = Snapshot.load(client, host());
            Target target = snapshot.resolve(r.getIpAddress(), r.getPort(), r.getVirtualServerName())
                    .orElseThrow(() -> new WorkflowExecutionException("No manageable endpoint for " + r.getIpAddress()
                            + ":" + r.getPort() + " (" + r.getVirtualServerName() + ")"));
            Optional<String> pem = new CertificateService(client).findBound(snapshot, target, r.getCertificateSerialNumber());
            if (pem.isEmpty()) {
                throw new WorkflowExecutionException("Certificate with serial " + r.getCertificateSerialNumber()
                        + " is not bound to " + r.getIpAddress() + ":" + r.getPort());
            }
            ValidateCertificateResponse<JsonNode> response = new ValidateCertificateResponse<>();
            response.setCertificate(pem.get());
            return response;
        } catch (WorkflowExecutionException e) {
            throw e;
        } catch (Exception e) {
            throw new WorkflowExecutionException("validateCertificate failed: " + e.getMessage(), e);
        }
    }

    /** Certificates from the chain embedded in the request, otherwise from the downloaded package. */
    List<X509Certificate> obtainCertificates(KempInstallRequest r) throws Exception {
        if (r.getCertificateChain() != null && !r.getCertificateChain().isBlank()) {
            return Pem.parseCertificates(r.getCertificateChain());
        }
        String link = r.getCertificateLink();
        if (link == null || !link.startsWith("https://")) {
            throw new WorkflowExecutionException("installCertificate needs an https certificateLink or a certificateChain");
        }
        List<X509Certificate> certificates = CertificatePackage.download(link);
        if (certificates.isEmpty()) {
            throw new WorkflowExecutionException("Certificate package contains no certificates");
        }
        return certificates;
    }

    /** The LoadMaster is already changed at this point, so a cleanup problem must not fail the action. */
    private void deleteKeyQuietly(String flowId) {
        try {
            keyStore.delete(flowId);
        } catch (Exception e) {
            log.warn("Could not delete the stored private key of flow {} (removed by expiry later): {}",
                    flowId, e.getMessage());
        }
    }
}
