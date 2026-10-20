package ch.admin.bj.swiyu.core.business.common.did;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.startsWith;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import ch.admin.bj.swiyu.core.business.common.exceptions.DidResolveException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
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
 * PQEID: a real hybrid DID log (did:webvh:1.0-pqeid, log proofs mldsa65-ed25519-jcs-pqeid, made by didtoolbox) is
 * accepted by the registry's schema and resolved by didresolver; its composite verification methods parse in nimbus.
 */
class HybridDidLogTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static String didLog;
    private static String did;

    @BeforeAll
    static void load() throws Exception {
        try (var in = HybridDidLogTest.class.getResourceAsStream("/did/hybrid-didlog.jsonl")) {
            didLog = new String(Objects.requireNonNull(in).readAllBytes(), StandardCharsets.UTF_8).trim();
        }
        did = MAPPER.readTree(firstEntry()).at("/state/id").asText();
    }

    private static String firstEntry() {
        return didLog.lines().findFirst().orElseThrow();
    }

    private static JsonSchema didwebvhSchema() throws Exception {
        try (var in = HybridDidLogTest.class.getResourceAsStream("/schema/didwebvh.schema.json")) {
            return JsonSchemaFactory.getInstance(SpecVersion.VersionFlag.V202012).getSchema(MAPPER.readTree(in));
        }
    }

    private static DidPublicKeyLoader loaderServing(String log) {
        RestClient client = mock(RestClient.class, Answers.RETURNS_DEEP_STUBS);
        when(client.get().uri(startsWith("https://identifier-reg.pqeid.g-roch.ch")).retrieve().body(String.class))
            .thenReturn(log);
        return new DidPublicKeyLoader(client, MAPPER);
    }

    @Test
    void fixture_isReallyAHybridLog() throws Exception {
        var entry = MAPPER.readTree(firstEntry());
        assertThat(entry.at("/parameters/method").asText()).isEqualTo("did:webvh:1.0-pqeid");
        assertThat(entry.at("/proof/0/cryptosuite").asText()).isEqualTo("mldsa65-ed25519-jcs-pqeid");
        assertThat(entry.at("/parameters/updateKeys/0").asText()).hasSizeGreaterThan(2_700); // composite multikey
    }

    @Test
    void registrySchema_acceptsHybridLog() throws Exception {
        assertThat(didwebvhSchema().validate(MAPPER.readTree(firstEntry()))).isEmpty();
    }

    @Test
    void registrySchema_rejectsUnknownMethodVersionAndSuite() throws Exception {
        var badMethod = firstEntry().replace("\"did:webvh:1.0-pqeid\"", "\"did:webvh:9.9\"");
        var badSuite = firstEntry().replace("\"mldsa65-ed25519-jcs-pqeid\"", "\"mldsa65-ed25519-jcs-other\"");
        assertThat(badMethod).isNotEqualTo(firstEntry());
        assertThat(badSuite).isNotEqualTo(firstEntry());
        assertThat(didwebvhSchema().validate(MAPPER.readTree(badMethod))).isNotEmpty();
        assertThat(didwebvhSchema().validate(MAPPER.readTree(badSuite))).isNotEmpty();
    }

    @Test
    void didResolver_resolvesHybridLog_andNimbusParsesTheCompositeKey() throws Exception {
        var jwk = loaderServing(didLog).loadJWK(did + "#assert-key-01");

        assertThat(jwk).isInstanceOf(CompositeMLDSAKey.class);
        assertThat(jwk.getAlgorithm()).isEqualTo(JWSAlgorithm.ML_DSA_65_ES256);
    }

    @Test
    void didResolver_refusesHybridLogWithATamperedProof() throws Exception {
        var entry = (ObjectNode) MAPPER.readTree(firstEntry());
        var proof = (ObjectNode) entry.at("/proof/0");
        var value = proof.get("proofValue").asText();
        var flipped = value.charAt(100) == 'A' ? 'B' : 'A';
        proof.put("proofValue", value.substring(0, 100) + flipped + value.substring(101));

        assertThatThrownBy(() -> loaderServing(MAPPER.writeValueAsString(entry)).loadJWK(did + "#assert-key-01"))
            .isInstanceOf(DidResolveException.class);
    }
}
