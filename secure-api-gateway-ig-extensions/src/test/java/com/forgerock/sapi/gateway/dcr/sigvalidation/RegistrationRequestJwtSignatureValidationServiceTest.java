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

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.AssertionsForClassTypes.catchThrowableOfType;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.reset;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.net.MalformedURLException;
import java.net.URL;
import java.security.SignatureException;
import java.util.concurrent.ExecutionException;

import org.forgerock.http.protocol.Response;
import org.forgerock.http.protocol.Status;
import org.forgerock.json.jose.exceptions.FailedToLoadJWKException;
import org.forgerock.json.jose.jwk.JWKSet;
import org.forgerock.json.jose.jws.SignedJwt;
import org.forgerock.util.promise.Promise;
import org.forgerock.util.promise.Promises;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import com.forgerock.sapi.gateway.dcr.common.DCRErrorCode;
import com.forgerock.sapi.gateway.dcr.models.RegistrationRequest;
import com.forgerock.sapi.gateway.dcr.models.SoftwareStatement;
import com.forgerock.sapi.gateway.jws.JwtSignatureValidator;

class RegistrationRequestJwtSignatureValidationServiceTest {

    private final JwksSupplierEmbeddedJwks JwksFromSoftwareStatementSupplier = mock(JwksSupplierEmbeddedJwks.class);
    private final JwksSupplierJwksUri jwksFromJwksUriSupplier = mock(JwksSupplierJwksUri.class);
    private final JwtSignatureValidator jwtSignatureValidator = mock(JwtSignatureValidator.class);
    private final RegistrationRequest registrationRequest = mock(RegistrationRequest.class);
    private final SoftwareStatement softwareStatement = mock(SoftwareStatement.class);
    private RegistrationRequestJwtSignatureValidationService registrationRequestJwtSignatureValidator;

    @BeforeEach
    void setUp() {
        registrationRequestJwtSignatureValidator = new RegistrationRequestJwtSignatureValidationService(
                JwksFromSoftwareStatementSupplier,
                jwksFromJwksUriSupplier,
                jwtSignatureValidator);
        when(registrationRequest.getSoftwareStatement()).thenReturn(softwareStatement);
    }

    @AfterEach
    void tearDown() {
        reset(JwksFromSoftwareStatementSupplier, jwksFromJwksUriSupplier, jwtSignatureValidator, registrationRequest,
                softwareStatement);
    }

    @Test
    void success_withJwksUri_validateJwtSignature() throws ExecutionException, InterruptedException {
        // Given
        JWKSet jwkSet = new JWKSet();
        SignedJwt signedJwt = mock(SignedJwt.class);
        when(softwareStatement.hasJwksUri()).thenReturn(true);
        when(jwksFromJwksUriSupplier.getJWKSet(eq(registrationRequest))).thenReturn(Promises.newResultPromise(jwkSet));
        when(registrationRequest.getSignedJwt()).thenReturn(signedJwt);

        // When
        Promise<Response, DCRSignatureValidationException> validationResponsePromise =
                registrationRequestJwtSignatureValidator.validateJwtSignature(registrationRequest);

        // Then
        Response validationResponse = validationResponsePromise.get();
        assertThat(validationResponse.getStatus()).isEqualTo(Status.OK);
        verify(jwksFromJwksUriSupplier, times(1)).getJWKSet(any());
        verify(JwksFromSoftwareStatementSupplier, never()).getJWKSet(any());
    }

    @Test
    void failsToLoadJwksFromJwksUri_withJwksUri_validateJwtSignature() throws SignatureException, MalformedURLException {
        // Given
        JWKSet jwkSet = new JWKSet();
        SignedJwt signedJwt = mock(SignedJwt.class);
        when(softwareStatement.hasJwksUri()).thenReturn(true);
        when(softwareStatement.getJwksUri()).thenReturn(new URL("https://jwks.com"));
        when(jwksFromJwksUriSupplier.getJWKSet(eq(registrationRequest))).thenReturn(Promises.newExceptionPromise(
                        new FailedToLoadJWKException("Failed to load jwks")));
        doThrow(new SignatureException("invalid jwt signature")).when(jwtSignatureValidator).validateSignature(signedJwt, jwkSet);
        // When
        Promise<Response, DCRSignatureValidationException> validationResponsePromise =
                registrationRequestJwtSignatureValidator.validateJwtSignature(registrationRequest);

        // Then
        DCRSignatureValidationException exception = catchThrowableOfType(validationResponsePromise::getOrThrow,
                DCRSignatureValidationException.class);
        assertThat(exception.getErrorCode()).isEqualTo(DCRErrorCode.INVALID_CLIENT_METADATA);
        verify(JwksFromSoftwareStatementSupplier, never()).getJWKSet(any());
    }

    @Test
    void failsInvalidJwtSignature_withJwksUri_validateJwtSignature() throws SignatureException, MalformedURLException {
        // Given
        JWKSet jwkSet = new JWKSet();
        SignedJwt signedJwt = mock(SignedJwt.class);
        when(softwareStatement.hasJwksUri()).thenReturn(true);
        when(softwareStatement.getJwksUri()).thenReturn(new URL("https://jwks.com"));
        when(jwksFromJwksUriSupplier.getJWKSet(eq(registrationRequest)))
                .thenReturn(Promises.newResultPromise(jwkSet));
        when(registrationRequest.getSignedJwt()).thenReturn(signedJwt);
        doThrow(new SignatureException("invalid jwt signature"))
                .when(jwtSignatureValidator).validateSignature(signedJwt, jwkSet);
        // When
        Promise<Response, DCRSignatureValidationException> validationResponsePromise =
                registrationRequestJwtSignatureValidator.validateJwtSignature(registrationRequest);

        // Then
        DCRSignatureValidationException exception = catchThrowableOfType(validationResponsePromise::getOrThrow,
                DCRSignatureValidationException.class);
        assertThat(exception.getErrorCode()).isEqualTo(DCRErrorCode.INVALID_CLIENT_METADATA);
        verify(JwksFromSoftwareStatementSupplier, never()).getJWKSet(any());
    }

    @Test
    void success_withEmbeddedJwks_validateJwtSignature() throws ExecutionException, InterruptedException {
        // Given
        JWKSet jwkSet = new JWKSet();
        SignedJwt signedJwt = mock(SignedJwt.class);
        when(softwareStatement.hasJwksUri()).thenReturn(false);
        when(JwksFromSoftwareStatementSupplier.getJWKSet(eq(registrationRequest))).thenReturn(Promises.newResultPromise(jwkSet));
        when(registrationRequest.getSignedJwt()).thenReturn(signedJwt);


        // When
        Promise<Response, DCRSignatureValidationException> validationResponsePromise =
                registrationRequestJwtSignatureValidator.validateJwtSignature(registrationRequest);

        // Then
        Response validationResponse = validationResponsePromise.get();
        assertThat(validationResponse.getStatus()).isEqualTo(Status.OK);
        verify(JwksFromSoftwareStatementSupplier, times(1)).getJWKSet(any());
        verify(jwksFromJwksUriSupplier, never()).getJWKSet(any());
    }

    @Test
    void invalidSigWithSsaEmbeddedJWKS_validateJwtSignature() throws SignatureException {
        // Given
        JWKSet jwkSet = new JWKSet();
        SignedJwt signedJwt = mock(SignedJwt.class);
        when(softwareStatement.hasJwksUri()).thenReturn(false);
        when(JwksFromSoftwareStatementSupplier.getJWKSet(eq(registrationRequest))).thenReturn(Promises.newResultPromise(jwkSet));
        when(registrationRequest.getSignedJwt()).thenReturn(signedJwt);
        doThrow(new SignatureException("invalid jwt signature")).when(jwtSignatureValidator).validateSignature(signedJwt, jwkSet);

        // When
        Promise<Response, DCRSignatureValidationException> validationResponsePromise =
                registrationRequestJwtSignatureValidator.validateJwtSignature(registrationRequest);

        // Then
        DCRSignatureValidationException exception = catchThrowableOfType(validationResponsePromise::getOrThrow,
                DCRSignatureValidationException.class);
        assertThat(exception.getErrorCode()).isEqualTo(DCRErrorCode.INVALID_CLIENT_METADATA);
        verify(JwksFromSoftwareStatementSupplier, times(1)).getJWKSet(any());
        verify(jwksFromJwksUriSupplier, never()).getJWKSet(any());
    }
}