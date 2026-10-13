package ch.admin.bj.swiyu.core.business.common.did;

import com.nimbusds.jose.JWSAlgorithm;
import jakarta.validation.constraints.NotEmpty;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;
import org.springframework.validation.annotation.Validated;

/**
 * PQEID: JWS algorithms the registry accepts for issuer-signed writes (status lists,
 * identifiers). Expand phase: ML-DSA-44 + composite; contract = drop ML-DSA-44 (config only).
 */
@Validated
@ConfigurationProperties(prefix = "app.signature")
public record SignaturePolicyProperties(
    @NotEmpty @DefaultValue({ "ML-DSA-44", "ML-DSA-65-ES256" }) List<String> acceptedAlgorithms
) {
    /** The policy as nimbus algorithms. */
    public Set<JWSAlgorithm> acceptedJwsAlgorithms() {
        return acceptedAlgorithms.stream().map(JWSAlgorithm::parse).collect(Collectors.toUnmodifiableSet());
    }
}