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
package com.forgerock.sapi.gateway.dcr.sigvalidation;

import static org.assertj.core.api.AssertionsForClassTypes.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.reset;
import static org.mockito.Mockito.when;

import java.util.Map;

import org.forgerock.json.jose.exceptions.FailedToLoadJWKException;
import org.forgerock.json.jose.jwk.JWKSet;
import org.forgerock.json.jose.jws.SignedJwt;
import org.forgerock.util.promise.Promise;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import com.forgerock.sapi.gateway.dcr.models.RegistrationRequest;
import com.forgerock.sapi.gateway.dcr.models.SoftwareStatement;
import com.forgerock.sapi.gateway.util.CryptoUtils;
import com.nimbusds.jose.JWSAlgorithm;

class JwksSupplierEmbeddedJwksTest {

    private JwksSupplierEmbeddedJwks jwksJwtSignatureValidator;
    private final RegistrationRequest registrationRequest = mock(RegistrationRequest.class);
    private final SoftwareStatement softwareStatement = mock(SoftwareStatement.class);

    @BeforeEach
    void setUp() {
        jwksJwtSignatureValidator = new JwksSupplierEmbeddedJwks();
        when(registrationRequest.getSoftwareStatement()).thenReturn(softwareStatement);
    }

    @AfterEach
    void tearDown() {
        reset(registrationRequest, softwareStatement);
    }

    @Test
    void success_validateRegistrationRequestJwtSignature() throws InterruptedException, FailedToLoadJWKException {
        // Given
        SignedJwt signedJwt = CryptoUtils.createSignedJwt(Map.of(), JWSAlgorithm.PS256);
        JWKSet jwkSet = CryptoUtils.createJwkSet();
        when(registrationRequest.getSignedJwt()).thenReturn(signedJwt);
        when(softwareStatement.getJwksSet()).thenReturn(jwkSet);

        // No need to mock validateSignature - it has a void return sign
        Promise<JWKSet, FailedToLoadJWKException> promise
                = jwksJwtSignatureValidator.getJWKSet(registrationRequest);
        JWKSet jwksSet = promise.getOrThrow();

        // Then
        assertThat(jwksSet).isEqualTo(jwkSet);
    }
}