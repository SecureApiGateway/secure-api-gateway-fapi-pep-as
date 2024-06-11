/*
 * Copyright © 2020-2024 ForgeRock AS (obst@forgerock.com)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.forgerock.sapi.gateway.jws;

import java.security.SignatureException;
import java.security.interfaces.RSAPublicKey;
import java.time.Clock;
import java.time.Instant;
import java.util.Set;

import org.forgerock.json.jose.jwk.JWK;
import org.forgerock.json.jose.jwk.JWKSet;
import org.forgerock.json.jose.jwk.RsaJWK;
import org.forgerock.json.jose.jws.JwsAlgorithm;
import org.forgerock.json.jose.jws.SignedJwt;
import org.forgerock.json.jose.jws.SigningManager;
import org.forgerock.json.jose.jws.handlers.SigningHandler;
import org.forgerock.json.jose.jwt.Algorithm;
import org.forgerock.openig.heap.GenericHeaplet;
import org.forgerock.openig.heap.HeapException;
import org.forgerock.secrets.SecretBuilder;
import org.forgerock.secrets.SecretsProvider;
import org.forgerock.secrets.keys.VerificationKey;
import org.forgerock.util.Reject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Validator that validates a JWT using an RSA Public Key.
 *
 * The RSA Public Key to use is determined by looking for a JWK within the supplied JWKSet which has a kid matching the kid
 * supplied in the JWT header. Validation will be failed if no JWK can be found to carry out the signature verification.
 */
public class RsaJwtSignatureValidator implements JwtSignatureValidator {

    private static final Logger log = LoggerFactory.getLogger(JwtSignatureValidator.class);
    public static final String USE_SIGNING_KEY = "sig";

    private final SigningManager signingManager = new SigningManager(new SecretsProvider(Clock.systemUTC()));

    private final Set<Algorithm> supportedAlgorithms = Set.of(JwsAlgorithm.PS256, JwsAlgorithm.PS384, JwsAlgorithm.PS512);

    @Override
    public void validateSignature(SignedJwt jwt, JWKSet jwkSet) throws SignatureException {
        try {
            Reject.ifNull(jwt, "jwt must be supplied");
            Reject.ifNull(jwkSet, "jwkSet must be supplied");

            String kid = jwt.getHeader().getKeyId();
            if (kid == null) {
                throw new SignatureException("kid must be present in the JWT header");
            }

            final JwsAlgorithm jwsAlgorithm = jwt.getHeader().getAlgorithm();
            if (!supportedAlgorithms.contains(jwsAlgorithm)) {
                throw new SignatureException("jwt signed using unsupported algorithm: " + jwsAlgorithm);
            }
            JWK jwk = jwkSet.findJwk(kid);
            if (jwk == null) {
                throw new SignatureException("jwk not found in supplied jwkSet for kid: " + kid);
            }
            if (!(jwk instanceof RsaJWK)) {
                throw new SignatureException("jwk for kid: " + kid + " must be of type RsaJwk");
            }
            if (!USE_SIGNING_KEY.equals(jwk.getUse())) {
                throw new SignatureException("jwk for kid: " + kid + " must be signing key, instead found: " + jwk.getUse());
            }

            log.debug("RsaJwtSignatureValidator() found jwk for kid. Signing algo supported, is RsaJwk, and is signing " +
                    "key. Validating signature");
            RSAPublicKey publicKey = ((RsaJWK) jwk).toRSAPublicKey();
            final SecretBuilder secretBuilder = new SecretBuilder().publicKey(publicKey)
                                                                   .expiresAt(Instant.MAX)
                                                                   .stableId(kid);
            final VerificationKey verificationKey = new VerificationKey(secretBuilder);
            SigningHandler verificationHandler = signingManager.newRsaVerificationHandler(verificationKey);
            if (!jwt.verify(verificationHandler)) {
                throw new SignatureException("jwt signature verification failed");
            }
        } catch (SignatureException se) {
            throw se;
        }
        catch (Throwable t) {
            throw new SignatureException(t);
        }
    }

    /**
     * Basic heaplet to allow RsaJwtSignatureValidator to be created via IG config
     */
    public static class Heaplet extends GenericHeaplet {
        @Override
        public Object create() throws HeapException {
            return new RsaJwtSignatureValidator();
        }
    }
}
