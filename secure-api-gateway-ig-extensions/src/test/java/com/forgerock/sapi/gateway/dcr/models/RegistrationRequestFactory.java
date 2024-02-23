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

import java.net.MalformedURLException;
import java.net.URL;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import com.forgerock.sapi.gateway.dcr.request.DCRRegistrationRequestBuilderException;
import com.forgerock.sapi.gateway.jws.JwtDecoder;
import com.forgerock.sapi.gateway.trusteddirectories.TrustedDirectory;
import com.forgerock.sapi.gateway.trusteddirectories.TrustedDirectoryService;
import com.forgerock.sapi.gateway.trusteddirectories.TrustedDirectoryTestFactory;
import com.forgerock.sapi.gateway.util.CryptoUtils;
import com.nimbusds.jose.JWSAlgorithm;

public class RegistrationRequestFactory {

    private static String JWKS_URI = "https://jwks.io";
    private static URL JWKS_URL;

    private static List<String> REDIRECT_URIS = List.of("https://domain1.com/callback", "https://domain2.com/callback");

    static {
        try {
            JWKS_URL = new URL(JWKS_URI);
        } catch (MalformedURLException e) {
            throw new RuntimeException(e);
        }
    }
    public static RegistrationRequest getRegRequestWithJwksUriSoftwareStatement(
            Map<String, Object> overrideRegRequestClaims, Map<String, Object> overrideSsaClaims)
            throws DCRRegistrationRequestBuilderException {

        Map<String, Object> ssaClaims = SoftwareStatementTestFactory.getValidJwksUriBasedSsaClaims(overrideSsaClaims);
        String ssab64EncodedJwtString = CryptoUtils.createEncodedJwtString(ssaClaims, JWSAlgorithm.PS256);
        Map<String, Object> registrationRequestClaims = new HashMap<>();
        registrationRequestClaims.put("iss", "Acme Ltd");
        registrationRequestClaims.put("software_statement", ssab64EncodedJwtString);
        registrationRequestClaims.put("redirect_uris", REDIRECT_URIS);
        registrationRequestClaims.putAll(overrideRegRequestClaims);

        String regRequestB64EncodedJwt = CryptoUtils.createEncodedJwtString(registrationRequestClaims, JWSAlgorithm.PS256);
        TrustedDirectoryService trustedDirectoryService = new TrustedDirectoryService() {
            @Override
            public TrustedDirectory getTrustedDirectoryConfiguration(String issuer) {
                return TrustedDirectoryTestFactory.getJwksUriBasedTrustedDirectory();
            }
        };
        SoftwareStatement.Builder ssBuilder = new SoftwareStatement.Builder(trustedDirectoryService, new JwtDecoder());
        RegistrationRequest.Builder builder = new RegistrationRequest.Builder(ssBuilder, new JwtDecoder());
        return builder.build(regRequestB64EncodedJwt);
    }

    public static RegistrationRequest getRegRequestWithJwksSoftwareStatement(
            Map<String, Object> overrideRegRequestClaims, Map<String, Object> overrideSsaClaims )
            throws DCRRegistrationRequestBuilderException {
        Map<String, Object> ssaClaims = SoftwareStatementTestFactory.getValidJwksBasedSsaClaims(overrideSsaClaims);
        ssaClaims.putAll(overrideSsaClaims);
        String ssab64EncodedJwtString = CryptoUtils.createEncodedJwtString(ssaClaims, JWSAlgorithm.PS256);

        Map<String, Object> registrationRequestClaims = new HashMap<>();
        registrationRequestClaims.put("iss", "Acme Ltd");
        registrationRequestClaims.put("software_statement", ssab64EncodedJwtString);
        registrationRequestClaims.put("redirect_uris", REDIRECT_URIS);
        registrationRequestClaims.putAll(overrideRegRequestClaims);

        String regRequestB64EncodedJwt = CryptoUtils.createEncodedJwtString(registrationRequestClaims, JWSAlgorithm.PS256);
        TrustedDirectoryService trustedDirectoryService = new TrustedDirectoryService() {
            @Override
            public TrustedDirectory getTrustedDirectoryConfiguration(String issuer) {
                return TrustedDirectoryTestFactory.getJwksBasedTrustedDirectory();
            }
        };

        SoftwareStatement.Builder ssBuilder = new SoftwareStatement.Builder(trustedDirectoryService, new JwtDecoder());
        RegistrationRequest.Builder builder = new RegistrationRequest.Builder(ssBuilder, new JwtDecoder());
        return builder.build(regRequestB64EncodedJwt);
    }


}
