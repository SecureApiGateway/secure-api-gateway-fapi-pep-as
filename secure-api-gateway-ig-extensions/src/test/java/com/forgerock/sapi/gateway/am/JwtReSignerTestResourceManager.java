/*
 * Copyright © 2020-2025 ForgeRock AS (obst@forgerock.com)
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
package com.forgerock.sapi.gateway.am;

import static org.forgerock.json.jose.utils.BigIntegerUtils.base64UrlEncodeUnsignedBigEndian;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.fail;

import java.security.KeyPair;
import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;
import java.time.Clock;
import java.time.Instant;
import java.util.Collections;
import java.util.Map;
import java.util.function.Consumer;

import org.forgerock.json.jose.jwk.JWKSet;
import org.forgerock.json.jose.jwk.RsaJWK;
import org.forgerock.secrets.NoSuchSecretException;
import org.forgerock.secrets.Purpose;
import org.forgerock.secrets.SecretBuilder;
import org.forgerock.secrets.SecretsProvider;
import org.forgerock.secrets.jwkset.JwkSetSecretStore;
import org.forgerock.secrets.keys.SigningKey;
import org.forgerock.secrets.keys.VerificationKey;
import org.forgerock.util.Options;

import com.forgerock.sapi.gateway.util.CryptoUtils;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSHeader.Builder;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

/**
 * Manager of JwtReSigner objects and resources needed to create and test these objects.
 *
 * Generates RSA private keys to use when testing, and is capable of verifying that JWTs have been signed correctly
 * with these keys.
 */
public class JwtReSignerTestResourceManager {

    private static final String ID_TOKEN_ISSUER = "openam";
    private static final String TOKEN_CLAIM_NAME = "tokenName";
    private static final String ID_TOKEN_TOKEN_CLAIM_VALUE = "id_token";
    private final JwtReSigner jwtReSigner;

    // AM related secrets
    private final RSASSASigner amJwtSigner;
    private final String amSigningKeyId;
    private final SecretsProvider amVerifyingSecretsProvider;
    private final Purpose<VerificationKey> amVerificationKeyPurpose;

    // OB releated secrets
    private final RSASSAVerifier obJwtVerifier;
    private final String obSigningKeyId;
    private final SecretsProvider obSigningSecretsProvider;
    private final Purpose<SigningKey> signingKeyPurpose = Purpose.SIGN;

    public JwtReSignerTestResourceManager() {
        // Generate a signing key for AM
        final KeyPair amKeyPair = CryptoUtils.generateRsaKeyPair();
        this.amJwtSigner = new RSASSASigner(amKeyPair.getPrivate());
        this.amSigningKeyId = "am-kid";

        // SecretsProvider used to verify that the JWT to re-sign was signed by AM.
        this.amVerifyingSecretsProvider = new SecretsProvider(Clock.systemUTC());

        // Create a JwkSetSecretStore using the AM public key, used in the filter to verify signs from AM
        final RSAPublicKey amPublicKey = (RSAPublicKey) amKeyPair.getPublic();
        final RsaJWK amSigningKeyJwk = RsaJWK.builder(base64UrlEncodeUnsignedBigEndian(amPublicKey.getModulus()),
                        base64UrlEncodeUnsignedBigEndian(amPublicKey.getPublicExponent()))
                .keyId(amSigningKeyId).build();

        final JWKSet amJwks = new JWKSet(amSigningKeyJwk);
        amVerifyingSecretsProvider.setDefaultStores(new JwkSetSecretStore(amJwks, Options.unmodifiableDefaultOptions()));

        // When using the JwkSetSecretStore, the verification key id is not used but needs to be valid as per the regex.
        this.amVerificationKeyPurpose = Purpose.purpose("any.value", VerificationKey.class);

        // Generate a signing key for OpenBanking directly, JWTs will be resigned with this key.
        final KeyPair obKeyPair = CryptoUtils.generateRsaKeyPair();
        this.obJwtVerifier = new RSASSAVerifier((RSAPublicKey) obKeyPair.getPublic());
        this.obSigningKeyId = "ob-kid";

        // SecretProvider used to produce the JWT signed with the OB signing key
        obSigningSecretsProvider = new SecretsProvider(Clock.systemUTC());
        try {
            obSigningSecretsProvider.useSpecificSecretForPurpose(signingKeyPurpose,
                    new SigningKey(new SecretBuilder().stableId(obSigningKeyId).secretKey(obKeyPair.getPrivate()).expiresAt(Instant.MAX)));
        } catch (NoSuchSecretException e) {
            throw new RuntimeException(e);
        }

        jwtReSigner = new JwtReSigner(amVerifyingSecretsProvider, amVerificationKeyPurpose, obSigningKeyId,
                obSigningSecretsProvider, signingKeyPurpose);
    }

    public JwtReSigner getJwtReSigner() {
        return jwtReSigner;
    }

    public SecretsProvider getAmVerifyingSecretsProvider() {
        return amVerifyingSecretsProvider;
    }

    public SecretsProvider getObSigningSecretsProvider() {
        return obSigningSecretsProvider;
    }

    public String getObSigningKeyId() {
        return obSigningKeyId;
    }

    public Purpose<VerificationKey> getAmVerificationKeyPurpose() {
        return amVerificationKeyPurpose;
    }

    public Purpose<SigningKey> getSigningKeyPurpose() {
        return signingKeyPurpose;
    }

    public String createAmSignedJwt(String jti) {
        return createSignedJwt(amJwtSigner, amSigningKeyId, jti);
    }

    public String createAmSignedJwt(String jti, Map<String, Object> additionalClaims) {
        return createSignedJwt(amJwtSigner, amSigningKeyId, jti, additionalClaims);
    }

    public String createAmSignedIdToken(String jti) {
        return createSignedIdToken(amJwtSigner, amSigningKeyId, jti);
    }

    public String createSignedIdToken(RSASSASigner signer, String kid, String jti) {
        return createSignedJwt(signer, kid, jti, Map.of("iss", ID_TOKEN_ISSUER,
                                                            TOKEN_CLAIM_NAME, ID_TOKEN_TOKEN_CLAIM_VALUE));
    }

    public String createSignedJwt(RSASSASigner signer, String kid, String jti) {
        return createSignedJwt(signer, kid, jti, Collections.emptyMap());
    }

    public String createSignedJwt(RSASSASigner signer, String kid, String jti, Map<String, Object> additionalClaims) {
        final JWTClaimsSet.Builder claimSetBuilder = new JWTClaimsSet.Builder().jwtID(jti);
        additionalClaims.forEach(claimSetBuilder::claim);
        final SignedJWT signedJWT = new SignedJWT(new Builder(JWSAlgorithm.PS256).keyID(kid).build(),
                                                  claimSetBuilder.build());
        try {
            signedJWT.sign(signer);
        } catch (JOSEException e) {
            throw new RuntimeException(e);
        }
        return signedJWT.serialize();
    }
    public void validateJwtHasBeenReSigned(String expectedJti, String reSignedJwtString) {
        validateJwtHasBeenReSigned(expectedJti, reSignedJwtString, ignored -> {});
    }


    public void validateJwtHasBeenReSigned(String expectedJti, String reSignedJwtString, Consumer<SignedJWT> additionalValidation) {
        final SignedJWT reSignedJwt;
        try {
            reSignedJwt = SignedJWT.parse(reSignedJwtString);
        } catch (ParseException e) {
            throw new RuntimeException(e);
        }
        try {
            reSignedJwt.verify(obJwtVerifier);
        } catch (JOSEException e) {
            fail("Failed to verify id_token was signed by ob key", e);
        }

        // Valid the header and claims match what is expected
        final JWSHeader header = reSignedJwt.getHeader();
        assertEquals(JWSAlgorithm.PS256, header.getAlgorithm());
        assertEquals(obSigningKeyId, header.getKeyID());
        final JWTClaimsSet jwtClaimsSet;
        try {
            jwtClaimsSet = reSignedJwt.getJWTClaimsSet();
        } catch (ParseException e) {
            throw new RuntimeException(e);
        }
        assertEquals(expectedJti, jwtClaimsSet.getJWTID());

        additionalValidation.accept(reSignedJwt);
    }

    public void validateIdTokenHasBeenReSigned(String expectedIdTokenJti, String idToken)  {
        validateJwtHasBeenReSigned(expectedIdTokenJti, idToken, reSignedJwt -> {
            try {
                final JWTClaimsSet jwtClaimsSet = reSignedJwt.getJWTClaimsSet();
                assertEquals(ID_TOKEN_ISSUER, jwtClaimsSet.getIssuer());
                assertEquals(ID_TOKEN_TOKEN_CLAIM_VALUE, jwtClaimsSet.getClaim(TOKEN_CLAIM_NAME));
                assertEquals(expectedIdTokenJti, jwtClaimsSet.getJWTID());
            } catch (ParseException e) {
                throw new RuntimeException(e);
            }
        });
    }
}
