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

import java.net.MalformedURLException;
import java.net.URL;
import java.util.Map;

import org.forgerock.json.jose.jwk.JWKSet;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import com.forgerock.sapi.gateway.dcr.common.DCRErrorCode;
import com.forgerock.sapi.gateway.dcr.request.DCRRegistrationRequestBuilderException;
import com.forgerock.sapi.gateway.dcr.sigvalidation.DCRTestHelpers;
import com.forgerock.sapi.gateway.jws.JwtDecoder;
import com.forgerock.sapi.gateway.trusteddirectories.TrustedDirectory;
import com.forgerock.sapi.gateway.trusteddirectories.TrustedDirectoryService;
import com.forgerock.sapi.gateway.trusteddirectories.TrustedDirectoryTestFactory;
import com.forgerock.sapi.gateway.util.CryptoUtils;
import com.nimbusds.jose.JWSAlgorithm;

class SoftwareStatementBuilderTest {

    private final TrustedDirectoryService trustedDirectoryService = TrustedDirectoryTestFactory.getTrustedDirectoryService();
    private final JwtDecoder jwtDecoder = new JwtDecoder();

    private static final String ISSUER = "SSA_Issuer";
    private static final String ORG_ID = "0015800001041RACME";
    private static final String ORG_NAME = "Acme Inc.";
    private static final String SOFTWARE_ID ="1234567890";
    private static final String SOFTWARE_CLIENT_NAME = "Acme App";
    private static final String JWKS_URI = "https://jwks.com";

    public SoftwareStatement.Builder builder;


    @BeforeEach
    void setUp() {
         builder = new SoftwareStatement.Builder(trustedDirectoryService, jwtDecoder);
    }

    @Test
    void successJwksUriBased_buildSoftwareStatement()
            throws DCRRegistrationRequestBuilderException, MalformedURLException {
        // Given
        Map<String, Object> ssaClaims = SoftwareStatementTestFactory.getValidJwksUriBasedSsaClaims(Map.of());
        String requestJwt = CryptoUtils.createEncodedJwtString(ssaClaims, JWSAlgorithm.PS256);

        // When
        SoftwareStatement softwareStatement = builder.build(requestJwt);

        // Then
        assertThat(softwareStatement).isNotNull();
        assertThat(softwareStatement.getOrgId()).isEqualTo(ORG_ID);
        assertThat(softwareStatement.getOrgName()).isEqualTo(ORG_NAME);
        assertThat(softwareStatement.getSoftwareId()).isEqualTo(SOFTWARE_ID);
        assertThat(softwareStatement.getClientName()).isEqualTo(SOFTWARE_CLIENT_NAME);
        assertThat(softwareStatement.hasJwksUri()).isTrue();
        assertThat(softwareStatement.getJwksUri()).isEqualTo(new URL(JWKS_URI));
    }

    @Test
    void successJwksBased_buildSoftwareStatement() throws DCRRegistrationRequestBuilderException {
        // Given
        Map<String, Object> ssaClaims = SoftwareStatementTestFactory.getValidJwksBasedSsaClaims(Map.of());
        String requestJwt = CryptoUtils.createEncodedJwtString(ssaClaims, JWSAlgorithm.PS256);

        // When
        SoftwareStatement softwareStatement = builder.build(requestJwt);

        // Then
        assertThat(softwareStatement).isNotNull();
        assertThat(softwareStatement.getOrgId()).isEqualTo(ORG_ID);
        assertThat(softwareStatement.getOrgName()).isEqualTo(ORG_NAME);
        assertThat(softwareStatement.getSoftwareId()).isEqualTo(SOFTWARE_ID);
        assertThat(softwareStatement.getClientName()).isEqualTo(SOFTWARE_CLIENT_NAME);
        assertThat(softwareStatement.hasJwksUri()).isFalse();
        JWKSet expectedJWkSet = JWKSet.parse(DCRTestHelpers.JWKS_JSON);
        assertThat(softwareStatement.getJwksSet()).isEqualTo(expectedJWkSet);
    }

    @Test
    void failInvalidJwt_buildSoftwareStatement() {
        // Given

        // When
        DCRRegistrationRequestBuilderException exception = catchThrowableOfType(()->
                        builder.build("not.valid.jwt"),
                DCRRegistrationRequestBuilderException.class);
        // Then
        assertThat(exception).isNotNull();
        assertThat(exception.getErrorCode()).isEqualTo(DCRErrorCode.INVALID_SOFTWARE_STATEMENT);
    }

    @Test
    void failNoIssuerClaim_buildSoftwareStatement() {
        // Given
        Map<String, Object> ssaClaims = new java.util.HashMap<>(SoftwareStatementTestFactory.getValidJwksBasedSsaClaims(Map.of()));
        ssaClaims.remove("iss");
        String requestJwt = CryptoUtils.createEncodedJwtString(ssaClaims, JWSAlgorithm.PS256);

        // When
        DCRRegistrationRequestBuilderException exception = catchThrowableOfType(()->
                builder.build(requestJwt), DCRRegistrationRequestBuilderException.class);
        // Then
        assertThat(exception).isNotNull();
        assertThat(exception.getErrorCode()).isEqualTo(DCRErrorCode.INVALID_SOFTWARE_STATEMENT);
    }

    @Test
    void failUnrecognisedIssuer_buildSoftwareStatement() {
        // Given
        Map<String, Object> ssaClaimOverrides = Map.of("iss", "unrecognisedIssuer");
        Map<String, Object> ssaClaims = SoftwareStatementTestFactory.getValidJwksBasedSsaClaims(ssaClaimOverrides);
        String requestJwt = CryptoUtils.createEncodedJwtString(ssaClaims, JWSAlgorithm.PS256);

        // When
        DCRRegistrationRequestBuilderException exception = catchThrowableOfType(()->
                builder.build(requestJwt), DCRRegistrationRequestBuilderException.class);
        // Then
        assertThat(exception).isNotNull();
        assertThat(exception.getErrorCode()).isEqualTo(DCRErrorCode.UNAPPROVED_SOFTWARE_STATEMENT);
    }

    @Test
    void failNoOrgId_buildSoftwareStatement() {
        // Given
        Map<String, Object> ssaClaims = SoftwareStatementTestFactory.getValidJwksBasedSsaClaims(Map.of());
        String ssaIssuer = (String)ssaClaims.get("iss");
        TrustedDirectory trustedDirectory = trustedDirectoryService.getTrustedDirectoryConfiguration(ssaIssuer);
        ssaClaims.remove(trustedDirectory.getSoftwareStatementOrgIdClaimName());
        String requestJwt = CryptoUtils.createEncodedJwtString(ssaClaims, JWSAlgorithm.PS256);

        // When
        DCRRegistrationRequestBuilderException exception = catchThrowableOfType(()->
                builder.build(requestJwt), DCRRegistrationRequestBuilderException.class);
        // Then
        assertThat(exception).isNotNull();
        assertThat(exception.getErrorCode()).isEqualTo(DCRErrorCode.INVALID_SOFTWARE_STATEMENT);
    }

    @Test
    void failNoSoftwareId_buildSoftwareStatement() {
        // Given
        Map<String, Object> ssaClaims = SoftwareStatementTestFactory.getValidJwksBasedSsaClaims(Map.of());
        String ssaIssuer = (String)ssaClaims.get("iss");
        TrustedDirectory trustedDirectory = trustedDirectoryService.getTrustedDirectoryConfiguration(ssaIssuer);
        ssaClaims.remove(trustedDirectory.getSoftwareStatementSoftwareIdClaimName());
        String requestJwt = CryptoUtils.createEncodedJwtString(ssaClaims, JWSAlgorithm.PS256);

        // When
        DCRRegistrationRequestBuilderException exception = catchThrowableOfType(()->
                builder.build(requestJwt), DCRRegistrationRequestBuilderException.class);
        // Then
        assertThat(exception).isNotNull();
        assertThat(exception.getErrorCode()).isEqualTo(DCRErrorCode.INVALID_SOFTWARE_STATEMENT);
    }

    @Test
    void failNoSoftwareClientName_buildSoftwareStatement() {
        // Given
        Map<String, Object> ssaClaims = SoftwareStatementTestFactory.getValidJwksBasedSsaClaims(Map.of());
        String ssaIssuer = (String)ssaClaims.get("iss");
        TrustedDirectory trustedDirectory = trustedDirectoryService.getTrustedDirectoryConfiguration(ssaIssuer);
        ssaClaims.remove(trustedDirectory.getSoftwareStatementClientNameClaimName());
        String requestJwt = CryptoUtils.createEncodedJwtString(ssaClaims, JWSAlgorithm.PS256);

        // When
        DCRRegistrationRequestBuilderException exception = catchThrowableOfType(()->
                builder.build(requestJwt), DCRRegistrationRequestBuilderException.class);
        // Then
        assertThat(exception).isNotNull();
        assertThat(exception.getErrorCode()).isEqualTo(DCRErrorCode.INVALID_SOFTWARE_STATEMENT);
    }

    @Test
    void failNoJwksUri_buildSoftwareStatement() {
        // Given
        Map<String, Object> ssaClaims = SoftwareStatementTestFactory.getValidJwksUriBasedSsaClaims(Map.of());
        String ssaIssuer = (String)ssaClaims.get("iss");
        TrustedDirectory trustedDirectory = trustedDirectoryService.getTrustedDirectoryConfiguration(ssaIssuer);
        ssaClaims.remove(trustedDirectory.getSoftwareStatementJwksUriClaimName());
        String requestJwt = CryptoUtils.createEncodedJwtString(ssaClaims, JWSAlgorithm.PS256);

        // When
        DCRRegistrationRequestBuilderException exception = catchThrowableOfType(()->
                builder.build(requestJwt), DCRRegistrationRequestBuilderException.class);
        // Then
        assertThat(exception).isNotNull();
        assertThat(exception.getErrorCode()).isEqualTo(DCRErrorCode.INVALID_SOFTWARE_STATEMENT);
    }

    @Test
    void failNoJwks_buildSoftwareStatement() {
        // Given
        Map<String, Object> ssaClaims = SoftwareStatementTestFactory.getValidJwksBasedSsaClaims(Map.of());
        String ssaIssuer = (String)ssaClaims.get("iss");
        TrustedDirectory trustedDirectory = trustedDirectoryService.getTrustedDirectoryConfiguration(ssaIssuer);
        ssaClaims.remove(trustedDirectory.getSoftwareStatementJwksClaimName());
        String requestJwt = CryptoUtils.createEncodedJwtString(ssaClaims, JWSAlgorithm.PS256);

        // When
        DCRRegistrationRequestBuilderException exception = catchThrowableOfType(()->
                builder.build(requestJwt), DCRRegistrationRequestBuilderException.class);
        // Then
        assertThat(exception).isNotNull();
        assertThat(exception.getErrorCode()).isEqualTo(DCRErrorCode.INVALID_SOFTWARE_STATEMENT);
    }

}