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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.net.URI;
import java.util.List;
import java.util.Map;

import org.forgerock.json.jose.jwk.JWKSet;
import org.forgerock.json.jose.jws.JwsHeader;
import org.forgerock.json.jose.jws.SignedJwt;
import org.forgerock.json.jose.jwt.JwtClaimsSet;
import org.junit.jupiter.api.Test;

import com.forgerock.sapi.gateway.dcr.models.ApiClient.ApiClientBuilder;

public class ApiClientTest {

    /**
     * Default SSA to use in the ApiClientBuilder, this is SSA is useful when we need a value to be set but do not
     * depend on its contents
     */
    private static final SignedJwt EMPTY_SSA = new SignedJwt(new JwsHeader(), new JwtClaimsSet(Map.of()), new byte[0], new byte[0]);
    private static final String CLIENT_NAME = "testClient";
    private static final String OAUTH2_CLIENT_ID = "1234-5678-9012-1234";
    private static final String SOFTWARE_CLIENT_ID = "softwareClientId543";
    private static final List<String> ROLES = List.of("AISP", "PISP", "CBPII");
    private static final JWKSet JWK_SET = new JWKSet();
    private static final ApiClientOrganisation API_CLIENT_ORGANISATION = new ApiClientOrganisation("orgId123", "Test Organisation");
    private static final URI JWKS_URI = URI.create("https://jwks.uri");

    @Test
    public void builderCreatesValidApiClients() {
        validateClientWithJwks(createBuilderWithJwks().build());
        validateClientWithJwksUri(createApiClientWithJwksUri(JWKS_URI));
    }
    
    private static void validateClientWithJwks(ApiClient apiClient) {
        validateCommonFields(apiClient);
        assertEquals(JWK_SET, apiClient.getJwks());
    }

    private static void validateClientWithJwksUri(ApiClient apiClient) {
        validateCommonFields(apiClient);
        assertEquals(JWKS_URI, apiClient.getJwksUri());
    }
    
    private static void validateCommonFields(ApiClient apiClient) {
        assertEquals(CLIENT_NAME, apiClient.getClientName());
        assertEquals(OAUTH2_CLIENT_ID, apiClient.getOAuth2ClientId());
        assertEquals(SOFTWARE_CLIENT_ID, apiClient.getSoftwareClientId());
        assertEquals(ROLES, apiClient.getRoles());
        assertEquals(API_CLIENT_ORGANISATION, apiClient.getOrganisation());
    }
    
    @Test
    public void failToBuildIfMandatoryFieldIsMissing() {
        assertEquals("oAuth2ClientId must be configured",
                assertThrows(NullPointerException.class, () -> new ApiClientBuilder().build()).getMessage());
    }

    @Test
    public void failToBuildIfJwksAndJwksUriFieldsAreMissing() {
        assertEquals("Exactly one of jwksUri or jwks must be configured",
                assertThrows(IllegalArgumentException.class,
                        () -> createBuilderWithJwks().setJwks(null).setJwksUri(null).build()).getMessage());
    }

    @Test
    public void failToBuildIfJwksAndJwksUriFieldsAreBothSet() {
        assertEquals("Exactly one of jwksUri or jwks must be configured",
                assertThrows(IllegalArgumentException.class, () -> createBuilderWithJwks().setJwksUri(JWKS_URI).build()).getMessage());
    }

    public static ApiClient createApiClientWithJwksUri(URI jwksUri) {
        return createBuilderWithJwks().setJwks(null).setJwksUri(jwksUri).build();
    }

    public static ApiClient createApiClientWithSoftwareStatementJwks(JWKSet jwkSet, String softwareStatementJwksClaimName) {
        final JwtClaimsSet claimsSet = new JwtClaimsSet();
        if (softwareStatementJwksClaimName != null) {
            claimsSet.setClaim(softwareStatementJwksClaimName, jwkSet.toJsonValue());
        }

        final ApiClientBuilder builder = createBuilderWithJwks();
        builder.setSoftwareStatementAssertion(new SignedJwt(new JwsHeader(), claimsSet, new byte[0], new byte[0]));
        return builder.build();
    }

    public static ApiClientBuilder createBuilderWithJwks() {
        return new ApiClientBuilder().setClientName(CLIENT_NAME)
                                     .setOAuth2ClientId(OAUTH2_CLIENT_ID)
                                     .setSoftwareClientId(SOFTWARE_CLIENT_ID)
                                     .setSoftwareStatementAssertion(EMPTY_SSA)
                                     .setJwksUri(null)
                                     .setRoles(ROLES)
                                     .setJwks(JWK_SET)
                                     .setOrganisation(API_CLIENT_ORGANISATION);
    }
}
