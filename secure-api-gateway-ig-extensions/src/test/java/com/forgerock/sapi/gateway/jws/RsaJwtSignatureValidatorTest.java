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


import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.security.SignatureException;
import java.util.Date;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.TimeUnit;

import org.forgerock.json.jose.common.JwtReconstruction;
import org.forgerock.json.jose.jwk.JWKSet;
import org.forgerock.json.jose.jws.SignedJwt;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSHeader.Builder;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

class RsaJwtSignatureValidatorTest {

    private static JWTClaimsSet EXAMPLE_CLAIMS_SET;
    private static RSAKey SIGNING_KEY;
    private static RSAKey TRANSPORT_KEY;
    private static JWKSet JWK_SET;

    private final RsaJwtSignatureValidator signatureValidator = new RsaJwtSignatureValidator();

    @BeforeAll
    public static void beforeAll() throws JOSEException {
        SIGNING_KEY = new RSAKeyGenerator(2048)
                .keyUse(KeyUse.SIGNATURE)
                .keyID(UUID.randomUUID().toString())
                .generate();

        TRANSPORT_KEY = new RSAKeyGenerator(2048)
                .keyUse(KeyUse.ENCRYPTION)
                .keyID(UUID.randomUUID().toString())
                .generate();

        final com.nimbusds.jose.jwk.JWKSet nimbusJwkSet = new com.nimbusds.jose.jwk.JWKSet(List.of(SIGNING_KEY, TRANSPORT_KEY));
        JWK_SET = JWKSet.parse(nimbusJwkSet.toString(true));

        EXAMPLE_CLAIMS_SET = new JWTClaimsSet.Builder().issuer("test-issuer")
                .audience("https://example.com")
                .subject("test-tpp")
                .claim("blah", "blah")
                .expirationTime(new Date(System.currentTimeMillis() + TimeUnit.MILLISECONDS.toMillis(5)))
                .build();
    }

    private static Builder defaultHeaderBuilder(RSAKey key) {
        return new Builder(JWSAlgorithm.PS256).keyID(key.getKeyID());
    }

    private static Builder headerBuilderUsingCustomKeyId(String keyId) {
        return new Builder(JWSAlgorithm.PS256).keyID(keyId);
    }

    private SignedJwt generateSignedJwt(RSAKey key, JWTClaimsSet claimsSet) {
        return generateSignedJwt(key, claimsSet, defaultHeaderBuilder(key));
    }

    private SignedJwt generateSignedJwt(RSAKey key, JWTClaimsSet claimsSet, JWSHeader.Builder jwsHeaderBuilder) {
        try {
            JWSSigner signer = new RSASSASigner(key);
            SignedJWT signedJWT = new SignedJWT(jwsHeaderBuilder.build(), claimsSet);
            signedJWT.sign(signer);
            return new JwtReconstruction().reconstructJwt(signedJWT.serialize(), SignedJwt.class);
        } catch (JOSEException ex) {
            throw new IllegalStateException(ex);
        }
    }

    private void checkVerificationFails(SignedJwt jwt, JWKSet jwkSet, String expectedError) {
        final SignatureException signatureException = assertThrows(SignatureException.class,
                () -> signatureValidator.validateSignature(jwt, jwkSet));
        assertThat(signatureException.getMessage()).contains(expectedError);
    }

    @Test
    void verifyJwtWithValidSignaturePS256() throws SignatureException {
        signatureValidator.validateSignature(generateSignedJwt(SIGNING_KEY, EXAMPLE_CLAIMS_SET), JWK_SET);
    }

    @Test
    void verifyJwtWithValidSignaturePS384() throws SignatureException {
        final SignedJwt ps384Jwt = generateSignedJwt(SIGNING_KEY, EXAMPLE_CLAIMS_SET,
                                                     new Builder(JWSAlgorithm.PS384).keyID(SIGNING_KEY.getKeyID()));
        signatureValidator.validateSignature(ps384Jwt, JWK_SET);
    }

    @Test
    void verifyJwtWithValidSignaturePS512() throws SignatureException {
        final SignedJwt ps512Jwt = generateSignedJwt(SIGNING_KEY, EXAMPLE_CLAIMS_SET,
                                                     new Builder(JWSAlgorithm.PS512).keyID(SIGNING_KEY.getKeyID()));
        signatureValidator.validateSignature(ps512Jwt, JWK_SET);
    }

    @Test
    void verificationsFailsIfKeyUseIsNotSig() {
        final SignedJwt jwt = generateSignedJwt(TRANSPORT_KEY, EXAMPLE_CLAIMS_SET);
        checkVerificationFails(jwt, JWK_SET, "jwk for kid: " + TRANSPORT_KEY.getKeyID() + " must be signing key, instead found: enc");
    }

    @Test
    void verificationFailsJwtSignatureInvalid() {
        // Sign the JWT with the transport key, override the kid in the header to be that of the signing key, verification will fail as sig will not be valid for signing key
        final SignedJwt signedJwt = generateSignedJwt(TRANSPORT_KEY, EXAMPLE_CLAIMS_SET, headerBuilderUsingCustomKeyId(SIGNING_KEY.getKeyID()));
        checkVerificationFails(signedJwt, JWK_SET, "jwt signature verification failed");
    }

    @Test
    void verificationFailsJwtSignatureInvalidDueToCorruptedPayload() throws JOSEException {
        JWSSigner signer = new RSASSASigner(SIGNING_KEY);
        SignedJWT signedJWT = new SignedJWT(defaultHeaderBuilder(SIGNING_KEY).build(), EXAMPLE_CLAIMS_SET);
        signedJWT.sign(signer);
        final String[] splitJwt = signedJWT.serialize().split("\\.");
        String invalidJwt = splitJwt[0] + '.' + splitJwt[1] + "A." + splitJwt[2]; // Add an extra char to the end of the payload to corrupt it
        checkVerificationFails(new JwtReconstruction().reconstructJwt(invalidJwt, SignedJwt.class), JWK_SET, "jwt signature verification failed");
    }

    @Test
    void verificationFailsWhenKidNotInJwks() {
        final SignedJwt jwt = generateSignedJwt(SIGNING_KEY, EXAMPLE_CLAIMS_SET, headerBuilderUsingCustomKeyId("unknown"));
        checkVerificationFails(jwt, JWK_SET, "jwk not found in supplied jwkSet for kid");
    }

    @Test
    void verificationFailsJwtHeaderMissingKid() {
        final SignedJwt jwt = generateSignedJwt(SIGNING_KEY, EXAMPLE_CLAIMS_SET, headerBuilderUsingCustomKeyId(null));
        checkVerificationFails(jwt, JWK_SET, "kid must be present in the JWT header");
    }

    @Test
    void verificationFailsUnsupportedAlgorithm() {
        final JWSAlgorithm unsupportedAlgo = JWSAlgorithm.RS256;
        final SignedJwt jwt = generateSignedJwt(SIGNING_KEY, EXAMPLE_CLAIMS_SET, new JWSHeader.Builder(unsupportedAlgo).keyID(SIGNING_KEY.getKeyID()));
        checkVerificationFails(jwt, JWK_SET, "jwt signed using unsupported algorithm: " + unsupportedAlgo.getName());
    }

    @Test
    void verificationFailsIfNullParamsSupplied() {
        checkVerificationFails(null, JWK_SET, "jwt must be supplied");
        checkVerificationFails(generateSignedJwt(SIGNING_KEY, EXAMPLE_CLAIMS_SET), null, "jwkSet must be supplied");
    }
}