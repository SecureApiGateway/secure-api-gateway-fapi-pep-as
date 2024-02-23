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
import static org.assertj.core.api.AssertionsForClassTypes.catchThrowableOfType;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.reset;
import static org.mockito.Mockito.when;

import java.net.MalformedURLException;
import java.net.URL;
import java.security.SignatureException;
import java.util.Map;

import org.forgerock.http.protocol.Response;
import org.forgerock.http.protocol.Status;
import org.forgerock.json.jose.jwk.JWKSet;
import org.forgerock.json.jose.jws.SignedJwt;
import org.forgerock.util.promise.Promise;
import org.forgerock.util.promise.Promises;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import com.forgerock.sapi.gateway.dcr.models.SoftwareStatement;
import com.forgerock.sapi.gateway.jwks.JwkSetService;
import com.forgerock.sapi.gateway.jws.JwtSignatureValidator;
import com.forgerock.sapi.gateway.util.CryptoUtils;
import com.nimbusds.jose.JWSAlgorithm;

class SoftwareStatementAssertionSignatureValidatorServiceTest {

    private SoftwareStatementAssertionSignatureValidatorService ssaSigValidator;
    private static final JwkSetService jwkSetService = mock(JwkSetService.class);
    private static final JwtSignatureValidator jwtSignatureValidator = mock(JwtSignatureValidator.class);
    private static final SoftwareStatement softwareStatement = mock(SoftwareStatement.class);
    private static final String SSA_ISSUER = "Acme Trusted Directory";


    @BeforeEach
    void setUp() {
        ssaSigValidator = new SoftwareStatementAssertionSignatureValidatorService(jwkSetService,
                jwtSignatureValidator);
    }

    @AfterEach
    void tearDown() {
        reset(jwkSetService, jwtSignatureValidator, softwareStatement);
    }

    @Test
    void failIfSignatureInvalid_validateSoftwareStatementAssertionSignature() throws Exception {
        // Given
        SignedJwt ssaSignedJwt = CryptoUtils.createSignedJwt(Map.of("iss", SSA_ISSUER),
                JWSAlgorithm.PS256);
        final String JWK_SET_URL_STR = "https://jwkset.com";
        final URL JWK_SET_URL = new URL(JWK_SET_URL_STR);
        final JWKSet JWKS_SET = new JWKSet();


        // When
        when(softwareStatement.getTrustedDirectoryJwksUrl()).thenReturn(JWK_SET_URL);
        when(softwareStatement.getSignedJwt()).thenReturn(ssaSignedJwt);
        when(softwareStatement.getJwksSet()).thenReturn(JWKS_SET);
        when(jwkSetService.getJwkSet(JWK_SET_URL)).thenReturn(
                Promises.newResultPromise(JWKS_SET));
        doThrow(new SignatureException("Invalid sig")).when(jwtSignatureValidator)
                .validateSignature(ssaSignedJwt, JWKS_SET);

        Promise<Response, DCRSignatureValidationException> promise =
                ssaSigValidator.validateJwtSignature(softwareStatement);

        // Then
        DCRSignatureValidationException exception = catchThrowableOfType(promise::getOrThrow,
                DCRSignatureValidationException.class);
        assertThat(exception.getMessage()).contains("Failed to validate SSA");
    }

    @Test
    void success_validateSoftwareStatementAssertionSignature()
            throws MalformedURLException, InterruptedException, DCRSignatureValidationException {
        // Given
        SignedJwt ssaSignedJwt = CryptoUtils.createSignedJwt(Map.of("iss", SSA_ISSUER),
                JWSAlgorithm.PS256);
        final String JWK_SET_URL_STR = "https://jwkset.com";
        final URL JWK_SET_URL = new URL(JWK_SET_URL_STR);
        final JWKSet JWKS_SET = new JWKSet();

        // When
        when(softwareStatement.getTrustedDirectoryJwksUrl()).thenReturn(JWK_SET_URL);
        when(softwareStatement.getSignedJwt()).thenReturn(ssaSignedJwt);
        when(jwkSetService.getJwkSet(JWK_SET_URL)).thenReturn(
                Promises.newResultPromise(JWKS_SET));

        Promise<Response, DCRSignatureValidationException> promise =
                ssaSigValidator.validateJwtSignature(softwareStatement);

        // Then
        Response response = promise.getOrThrow();
        assertThat(response).isNotNull();
        assertThat(response.getStatus()).isEqualTo(Status.OK);
    }
}