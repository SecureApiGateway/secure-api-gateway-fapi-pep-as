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
package com.forgerock.sapi.gateway.dcr.models;

import static org.assertj.core.api.AssertionsForClassTypes.assertThat;
import static org.assertj.core.api.AssertionsForClassTypes.catchThrowableOfType;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.reset;
import static org.mockito.Mockito.when;

import java.util.List;
import java.util.Map;

import org.forgerock.json.jose.jws.SignedJwt;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import com.forgerock.sapi.gateway.common.jwt.JwtException;
import com.forgerock.sapi.gateway.dcr.common.DCRErrorCode;
import com.forgerock.sapi.gateway.dcr.request.DCRRegistrationRequestBuilderException;
import com.forgerock.sapi.gateway.jws.JwtDecoder;
import com.forgerock.sapi.gateway.util.CryptoUtils;
import com.nimbusds.jose.JWSAlgorithm;

class RegistrationRequestBuilderTest {

    private RegistrationRequest.Builder builder;
    private final SoftwareStatement.Builder softwareStatementBuilder = mock(SoftwareStatement.Builder.class);
    private final JwtDecoder jwtDecoder = mock(JwtDecoder.class);
    private final static String B64_ENCODED_REG_REQUEST_JWT = "header.payload.sig";


    @BeforeEach
    void setUp() {
        builder = new RegistrationRequest.Builder(softwareStatementBuilder, jwtDecoder);
    }

    @AfterEach
    void tearDown() {
        reset(softwareStatementBuilder, jwtDecoder);
    }

    @Test
    void success_build() throws JwtException, DCRRegistrationRequestBuilderException {
        // Given
        String softwareStatementb64EncodedString = "header.payload.sig";
        Map<String, Object> claims = Map.of("iss", "Acme App", "software_statement", softwareStatementb64EncodedString,
                "redirect_uris", List.of("https://domain1.com/callback"));
        SignedJwt regRequestSignedJwt = CryptoUtils.createSignedJwt(claims, JWSAlgorithm.PS256);
        // When
        when(jwtDecoder.getSignedJwt(B64_ENCODED_REG_REQUEST_JWT)).thenReturn(regRequestSignedJwt);
        SoftwareStatement softwareStatement = mock(SoftwareStatement.class);
        when(softwareStatementBuilder.build(softwareStatementb64EncodedString)).thenReturn(
                softwareStatement);
        RegistrationRequest registrationReqeuest = builder.build(B64_ENCODED_REG_REQUEST_JWT);

        // Then
        assertThat(registrationReqeuest).isNotNull();
        assertThat(registrationReqeuest.getSoftwareStatement()).isNotNull();
        assertThat(registrationReqeuest.getSignedJwt()).isEqualTo(regRequestSignedJwt);
    }

    @Test
    void throwsExceptionWhenInvalidEncodedJwtString() throws JwtException {
        // Given

        // When
        when(jwtDecoder.getSignedJwt(B64_ENCODED_REG_REQUEST_JWT)).thenThrow(new JwtException("invalid jwt"));

        DCRRegistrationRequestBuilderException exception = catchThrowableOfType(
                ()->builder.build(B64_ENCODED_REG_REQUEST_JWT), DCRRegistrationRequestBuilderException.class);

        // Then
        assertThat(exception).isNotNull();
        assertThat(exception.getErrorCode()).isEqualTo(DCRErrorCode.INVALID_CLIENT_METADATA);
    }

    @Test
    void throwsExceptionWhenNoIssuerClaimInRequestJwt() throws JwtException {
        // Given
        String softwareStatementb64EncodedString = "header.payload.sig";
        Map<String, Object> claims = Map.of("software_statement", softwareStatementb64EncodedString);
        SignedJwt regRequestSignedJwt = CryptoUtils.createSignedJwt(claims, JWSAlgorithm.PS256);
        // When
        when(jwtDecoder.getSignedJwt(B64_ENCODED_REG_REQUEST_JWT)).thenReturn(regRequestSignedJwt);

        DCRRegistrationRequestBuilderException exception = catchThrowableOfType(
                ()->builder.build(B64_ENCODED_REG_REQUEST_JWT), DCRRegistrationRequestBuilderException.class);

        // Then
        assertThat(exception).isNotNull();
        assertThat(exception.getErrorCode()).isEqualTo(DCRErrorCode.INVALID_CLIENT_METADATA);
    }

    @Test
    void throwsExceptionWhenNoSoftwareStatementClaimInRequestJwt() throws JwtException {
        // Given
        Map<String, Object> claims = Map.of("iss", "Acme App");
        SignedJwt regRequestSignedJwt = CryptoUtils.createSignedJwt(claims, JWSAlgorithm.PS256);
        // When
        when(jwtDecoder.getSignedJwt(B64_ENCODED_REG_REQUEST_JWT)).thenReturn(regRequestSignedJwt);
        DCRRegistrationRequestBuilderException exception = catchThrowableOfType(
                ()->builder.build(B64_ENCODED_REG_REQUEST_JWT), DCRRegistrationRequestBuilderException.class);

        // Then
        assertThat(exception).isNotNull();
        assertThat(exception.getErrorCode()).isEqualTo(DCRErrorCode.INVALID_CLIENT_METADATA);
    }

    @Test
    void throwsExceptionWhenSoftwareStatementBuilderFails()
            throws JwtException, DCRRegistrationRequestBuilderException {
        // Given
        String softwareStatementb64EncodedString = "header.payload.sig";
        Map<String, Object> claims = Map.of("iss", "Acme App", "software_statement", softwareStatementb64EncodedString);
        SignedJwt regRequestSignedJwt = CryptoUtils.createSignedJwt(claims, JWSAlgorithm.PS256);
        // When
        when(jwtDecoder.getSignedJwt(B64_ENCODED_REG_REQUEST_JWT)).thenReturn(regRequestSignedJwt);
        when(softwareStatementBuilder.build(softwareStatementb64EncodedString)).thenThrow(
                new DCRRegistrationRequestBuilderException(DCRErrorCode.INVALID_CLIENT_METADATA, "error"));

        DCRRegistrationRequestBuilderException exception = catchThrowableOfType(
                ()->builder.build(B64_ENCODED_REG_REQUEST_JWT), DCRRegistrationRequestBuilderException.class);

        // Then
        assertThat(exception).isNotNull();
        assertThat(exception.getErrorCode()).isEqualTo(DCRErrorCode.INVALID_CLIENT_METADATA);
    }
}