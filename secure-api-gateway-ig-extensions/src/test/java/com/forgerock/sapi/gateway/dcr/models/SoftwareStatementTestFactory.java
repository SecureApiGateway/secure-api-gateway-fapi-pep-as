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

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.forgerock.json.JsonValue;

import com.forgerock.sapi.gateway.dcr.sigvalidation.DCRTestHelpers;
import com.forgerock.sapi.gateway.trusteddirectories.TrustedDirectory;
import com.forgerock.sapi.gateway.trusteddirectories.TrustedDirectoryTestFactory;

public class SoftwareStatementTestFactory {
    private static final String ORG_ID = "0015800001041RACME";
    private static final String ORG_NAME= "Acme Inc.";
    private static final String SOFTWARE_ID ="1234567890";
    private static final String SOFTWARE_CLIENT_NAME = "Acme App";
    private static final String JWKS_URI = "https://jwks.com";
    private static final JsonValue JWKS_SET;
    private static final List<String> REDIRECT_URIS =
            List.of("https://domain1.io/callback", "https://domain2.io.callback");
    private static final List<String> ROLES = List.of("AISP", "PISP", "CBPII");

    static {
        JWKS_SET = DCRTestHelpers.getJwksJsonValue();
    }

    public static Map<String, Object> getValidJwksUriBasedSsaClaims(Map<String, Object> overrideSsaClaims){
        TrustedDirectory directory = TrustedDirectoryTestFactory.getJwksUriBasedTrustedDirectory();
        Map<String, Object> claims = new HashMap<>();
        claims.put("iss", directory.getIssuer());
        claims.put(directory.getSoftwareStatementOrgIdClaimName(), ORG_ID);
        claims.put(directory.getSoftwareStatementOrgNameClaimName(), ORG_NAME);
        claims.put(directory.getSoftwareStatementSoftwareIdClaimName(), SOFTWARE_ID);
        claims.put(directory.getSoftwareStatementJwksUriClaimName(), JWKS_URI);
        claims.put(directory.getSoftwareStatementRedirectUrisClaimName(), REDIRECT_URIS);
        claims.put(directory.getSoftwareStatementRolesClaimName(), ROLES);
        claims.put(directory.getSoftwareStatementClientNameClaimName(), SOFTWARE_CLIENT_NAME);
        claims.putAll(overrideSsaClaims);
        return claims;
    };

    public static Map<String, Object> getValidJwksBasedSsaClaims(Map<String, Object> overrideSsaClaims) {
        TrustedDirectory directory = TrustedDirectoryTestFactory.getEmbeddedJwksBasedDirectoryIssuer();

        Map<String, Object> claims = new HashMap<>();
        claims.put("iss", directory.getIssuer());
        claims.put(directory.getSoftwareStatementOrgIdClaimName(), ORG_ID);
        claims.put(directory.getSoftwareStatementOrgNameClaimName(), ORG_NAME);
        claims.put(directory.getSoftwareStatementSoftwareIdClaimName(), SOFTWARE_ID);
        claims.put(directory.getSoftwareStatementJwksClaimName(), JWKS_SET.getObject());
        claims.put(directory.getSoftwareStatementRedirectUrisClaimName(), REDIRECT_URIS);
        claims.put(directory.getSoftwareStatementRolesClaimName(), ROLES);
        claims.put(directory.getSoftwareStatementClientNameClaimName(), SOFTWARE_CLIENT_NAME);
        claims.putAll(overrideSsaClaims);
        return claims;
    }
}
