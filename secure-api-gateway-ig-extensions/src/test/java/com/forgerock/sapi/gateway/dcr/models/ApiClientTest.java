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

import java.util.List;
import java.util.Map;

import org.forgerock.json.jose.exceptions.FailedToLoadJWKException;
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
    private static final SignedJwt EMPTY_SSA = new SignedJwt(new JwsHeader(),
                                                             new JwtClaimsSet(Map.of()),
                                                             new byte[0],
                                                             new byte[0]);
    private static final String CLIENT_NAME = "testClient";
    private static final String OAUTH2_CLIENT_ID = "1234-5678-9012-1234";
    private static final String SOFTWARE_CLIENT_ID = "softwareClientId543";
    private static final List<String> ROLES = List.of("AISP", "PISP", "CBPII");
    private static final ApiClientOrganisation API_CLIENT_ORGANISATION = new ApiClientOrganisation("orgId123",
                                                                                                   "Test Organisation");
    private static final JWKSet EMBEDDED_JWKS = new JWKSet();

    public static ApiClientBuilder createBuilder(final JWKSet embeddedJwks) {
        return createBuilderWithoutJwkSetSupplier().withEmbeddedJwksSupplier(embeddedJwks);
    }

    private static ApiClientBuilder createBuilderWithoutJwkSetSupplier() {
        return ApiClient.builder().clientName(CLIENT_NAME)
                        .oAuth2ClientId(OAUTH2_CLIENT_ID)
                        .softwareClientId(SOFTWARE_CLIENT_ID)
                        .softwareStatementAssertion(EMPTY_SSA)
                        .roles(ROLES)
                        .organisation(API_CLIENT_ORGANISATION);
    }

    @Test
    public void builderCreatesValidApiClient() throws Exception {
        validateCommonFields(createBuilder(EMBEDDED_JWKS).build());
    }

    private static void validateCommonFields(ApiClient apiClient) throws FailedToLoadJWKException, InterruptedException {
        validateCommonFields(apiClient, false);
    }

    private static void validateCommonFields(ApiClient apiClient, boolean expectDeleted)
            throws FailedToLoadJWKException, InterruptedException {

        assertEquals(CLIENT_NAME, apiClient.getClientName());
        assertEquals(OAUTH2_CLIENT_ID, apiClient.getOAuth2ClientId());
        assertEquals(SOFTWARE_CLIENT_ID, apiClient.getSoftwareClientId());
        assertEquals(EMPTY_SSA, apiClient.getSoftwareStatementAssertion());
        assertEquals(ROLES, apiClient.getRoles());
        assertThrows(RuntimeException.class, () -> apiClient.getRoles().add("anotherRole"));

        assertEquals(API_CLIENT_ORGANISATION, apiClient.getOrganisation());
        assertEquals(EMBEDDED_JWKS, apiClient.getJwkSet().getOrThrow());
        assertEquals(expectDeleted, apiClient.isDeleted());
    }

    @Test
    public void builderCreatesApiClientMarkedAsDeleted() throws Exception {
        validateCommonFields(createBuilder(EMBEDDED_JWKS).deleted(true).build(), true);
    }

    @Test
    public void failToBuildIfMandatoryFieldIsMissing() {
        assertEquals("oAuth2ClientId must be configured",
                     assertThrows(NullPointerException.class, () -> ApiClient.builder().build())
                             .getMessage());
    }

    @Test
    public void failToBuildIfJwksSupplierIsNotConfigured() {
        final NullPointerException npe = assertThrows(NullPointerException.class,
                                                      () -> createBuilderWithoutJwkSetSupplier().build());
        assertEquals("jwkSetSupplier must be configured - please call withUriJwksSupplier or withEmbeddedJwksSupplier",
                     npe.getMessage());
    }

}
