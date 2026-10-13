package ch.admin.bj.swiyu.core.business.common.did;

import ch.admin.bj.swiyu.core.business.common.exceptions.CryptoIntegrityValidationFailedException;
import ch.admin.bj.swiyu.core.business.common.exceptions.DidResolveException;
import ch.admin.bj.swiyu.jwtutil.SignatureVerifiers;
import ch.admin.bj.swiyu.jwtutil.JwtUtilException;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jwt.SignedJWT;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
public class CryptoIntegrityValidator {

    private final DidPublicKeyLoader didPublicKeyLoader;
        private final SignaturePolicyProperties signaturePolicy;

    public void checkJwtCryptoIntegrity(SignedJWT vc) throws CryptoIntegrityValidationFailedException {
        var keyId = vc.getHeader().getKeyID();
        if (keyId == null || keyId.isEmpty()) {
            throw new CryptoIntegrityValidationFailedException("VC does not contain a key id.", null);
        }

        try {
            var jwk = didPublicKeyLoader.loadJWK(keyId);
            // PQEID: verifier from the DID key's type, gated by the registry's algorithm policy
            var verifier = SignatureVerifiers.forKey(jwk, vc.getHeader().getAlgorithm(),
                signaturePolicy.acceptedJwsAlgorithms());
            if (!vc.verify(verifier)) {
                throw new CryptoIntegrityValidationFailedException("Public key verification failed", null);
            }
        } catch (DidResolveException e) {
            throw new CryptoIntegrityValidationFailedException("VC references DID which cannot be resolved.", e);
        } catch (JwtUtilException e) {
            throw new CryptoIntegrityValidationFailedException("Key/algorithm not acceptable: " + e.getMessage(), e);
        } catch (JOSEException e) {
            throw new CryptoIntegrityValidationFailedException("VC could not be parsed.", e);
        }
    }
}
