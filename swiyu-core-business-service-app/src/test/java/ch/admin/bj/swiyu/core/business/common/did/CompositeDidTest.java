package ch.admin.bj.swiyu.core.business.common.did;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.startsWith;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.networknt.schema.JsonSchema;
import com.networknt.schema.JsonSchemaFactory;
import com.networknt.schema.SpecVersion;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.CompositeMLDSAKey;
import java.nio.charset.StandardCharsets;
import java.util.Objects;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.mockito.Answers;
import org.springframework.web.client.RestClient;

/**
 * PQEID: a real DID log made by didtoolbox, with composite (ML-DSA-65-ES256) verification methods,
 * is accepted by the registry's schema, resolved by didresolver and parsed by nimbus as a composite key.
 */
class CompositeDidTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static String didLog;
    private static String did;

    @BeforeAll
    static void load() throws Exception {
        try (var in = CompositeDidTest.class.getResourceAsStream("/did/composite-didlog.jsonl")) {
            didLog = new String(Objects.requireNonNull(in).readAllBytes(), StandardCharsets.UTF_8).trim();
        }
        did = MAPPER.readTree(firstEntry()).at("/state/id").asText();
    }

    private static String firstEntry() {
        return didLog.lines().findFirst().orElseThrow();
    }

    private static JsonSchema didwebvhSchema() throws Exception {
        try (var in = CompositeDidTest.class.getResourceAsStream("/schema/didwebvh.schema.json")) {
            return JsonSchemaFactory.getInstance(SpecVersion.VersionFlag.V202012).getSchema(MAPPER.readTree(in));
        }
    }

    @Test
    void registrySchema_acceptsCompositeVerificationMethods() throws Exception {
        assertThat(didwebvhSchema().validate(MAPPER.readTree(firstEntry()))).isEmpty();
    }

    @Test
    void registrySchema_rejectsUnknownAkpAlg() throws Exception {
        var tampered = firstEntry().replace("\"ML-DSA-65-ES256\"", "\"ML-DSA-65-ES999\"");
        assertThat(tampered).isNotEqualTo(firstEntry());
        assertThat(didwebvhSchema().validate(MAPPER.readTree(tampered))).isNotEmpty();
    }

    @Test
    void didResolver_resolvesCompositeKey_andNimbusParsesIt() throws Exception {
        RestClient client = mock(RestClient.class, Answers.RETURNS_DEEP_STUBS);
        when(client.get().uri(startsWith("https://identifier-reg.pqeid.g-roch.ch")).retrieve().body(String.class))
            .thenReturn(didLog);
        var loader = new DidPublicKeyLoader(client, MAPPER);

        var jwk = loader.loadJWK(did + "#assert-key-01");

        assertThat(jwk).isInstanceOf(CompositeMLDSAKey.class);
        assertThat(jwk.getAlgorithm()).isEqualTo(JWSAlgorithm.ML_DSA_65_ES256);
        assertThat(jwk.size()).isEqualTo(2017 * 8);
    }
}