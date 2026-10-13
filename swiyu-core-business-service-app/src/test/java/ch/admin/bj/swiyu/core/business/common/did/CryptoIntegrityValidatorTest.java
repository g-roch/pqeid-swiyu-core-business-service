/*
 * SPDX-FileCopyrightText: 2025 Swiss Confederation
 *
 * SPDX-License-Identifier: MIT
 */

package ch.admin.bj.swiyu.core.business.common.did;

import static ch.admin.bj.swiyu.core.business.modules.trust.service.onboarding.ProofOfPossessionKeyUtils.*;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import ch.admin.bj.swiyu.core.business.common.exceptions.CryptoIntegrityValidationFailedException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.CompositeSigner;
import com.nimbusds.jose.crypto.MLDSASigner;
import com.nimbusds.jose.jwk.CompositeMLDSAKey;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.gen.MLDSAKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jwt.SignedJWT;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.text.ParseException;
import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class CryptoIntegrityValidatorTest {

    DidPublicKeyLoader didPublicKeyLoader;

    CryptoIntegrityValidator cryptoIntegrityValidator;

    @BeforeAll
    static void registerBc() {
        java.security.Security.addProvider(com.nimbusds.jose.crypto.bc.BouncyCastleProviderSingleton.getInstance());
    }

    @BeforeEach
    void beforeEach() {
        didPublicKeyLoader = mock(DidPublicKeyLoader.class);
        cryptoIntegrityValidator = new CryptoIntegrityValidator(didPublicKeyLoader,
            new SignaturePolicyProperties(java.util.List.of("ML-DSA-44", "ML-DSA-65-ES256")));
    }

    /** A JWT with kid {@code kid}, signed by {@code signer} under {@code alg}. */
    private static SignedJWT signed(JWSAlgorithm alg, String kid, JWSSigner signer) throws JOSEException {
        var jwt = new SignedJWT(new JWSHeader.Builder(alg).keyID(kid).build(),
            new JWTClaimsSet.Builder().issuer("did:example:123").build());
        jwt.sign(signer);
        return jwt;
    }

    @Test
    void validate_failsWithEmptyKeyId()
        throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, JOSEException, ParseException {
        var did = "did:example:123";
        var kp1 = generateKeyPair();
        var signer1 = getSigner(kp1.getPrivate());
        var jwt = getPoPSubmission("nonce", did, "", signer1);
        var signedJwt = SignedJWT.parse(jwt);

        Assertions.assertThatExceptionOfType(CryptoIntegrityValidationFailedException.class)
            .isThrownBy(() -> cryptoIntegrityValidator.checkJwtCryptoIntegrity(signedJwt))
            .withMessageContaining("VC does not contain a key id.");
    }

    /** Signed by A, but the DID publishes B: an accepted key type, a wrong signature. */
    @Test
    void validate_failsWithMismatchingKeyMaterialId() throws Exception {
        var a = new MLDSAKeyGenerator(JWSAlgorithm.ML_DSA_44).generate();
        var b = new MLDSAKeyGenerator(JWSAlgorithm.ML_DSA_44).generate();
        var jwt = signed(JWSAlgorithm.ML_DSA_44, "did:example:123#suffix", new MLDSASigner(a));
        when(didPublicKeyLoader.loadJWK("did:example:123#suffix")).thenReturn(b.toPublicJWK());

        Assertions.assertThatExceptionOfType(CryptoIntegrityValidationFailedException.class)
            .isThrownBy(() -> cryptoIntegrityValidator.checkJwtCryptoIntegrity(jwt))
            .withMessageContaining("Public key verification failed");
    }

    @Test
    void validate_compositeSignedWrite_succeeds() throws Exception {
        var kp = java.security.KeyPairGenerator.getInstance("MLDSA65-ECDSA-P256-SHA512", "BC").generateKeyPair();
        var key = CompositeMLDSAKey.fromJCA(kp.getPublic(), kp.getPrivate());
        var jwt = signed(JWSAlgorithm.ML_DSA_65_ES256, "did:example:123#key-1", new CompositeSigner(key));
        when(didPublicKeyLoader.loadJWK("did:example:123#key-1")).thenReturn(key.toPublicJWK());

        Assertions.assertThatNoException().isThrownBy(() -> cryptoIntegrityValidator.checkJwtCryptoIntegrity(jwt));
    }

    /** Fail closed: a classical-only (ES256) issuer write is refused by the registry. */
    @Test
    void validate_classicalEcWrite_isRefused() throws Exception {
        var kp = generateKeyPair();   // EC P-256 (ProofOfPossessionKeyUtils)
        var ecJwk = new ECKey.Builder(Curve.P_256, (java.security.interfaces.ECPublicKey) kp.getPublic())
            .algorithm(JWSAlgorithm.ES256).build();
        var jwt = signed(JWSAlgorithm.ES256, "did:example:123#ec", getSigner(kp.getPrivate()));
        when(didPublicKeyLoader.loadJWK("did:example:123#ec")).thenReturn(ecJwk);

        Assertions.assertThatExceptionOfType(CryptoIntegrityValidationFailedException.class)
            .isThrownBy(() -> cryptoIntegrityValidator.checkJwtCryptoIntegrity(jwt))
            .withMessageContaining("not accepted");
    }

    @Test
    void validate_contractPolicy_refusesMldsa44() throws Exception {
        cryptoIntegrityValidator = new CryptoIntegrityValidator(didPublicKeyLoader,
            new SignaturePolicyProperties(java.util.List.of("ML-DSA-65-ES256")));
        var key = new MLDSAKeyGenerator(JWSAlgorithm.ML_DSA_44).generate();
        var jwt = signed(JWSAlgorithm.ML_DSA_44, "did:example:123#k", new MLDSASigner(key));
        when(didPublicKeyLoader.loadJWK("did:example:123#k")).thenReturn(key.toPublicJWK());

        Assertions.assertThatExceptionOfType(CryptoIntegrityValidationFailedException.class)
            .isThrownBy(() -> cryptoIntegrityValidator.checkJwtCryptoIntegrity(jwt))
            .withMessageContaining("not accepted");
    }
}
