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
package com.forgerock.sapi.gateway.jwks;

import static com.forgerock.sapi.gateway.dcr.models.ApiClientTest.createApiClientWithSoftwareStatementJwks;
import static org.forgerock.json.JsonValue.field;
import static org.forgerock.json.JsonValue.json;
import static org.forgerock.json.JsonValue.object;
import static org.junit.jupiter.api.Assertions.*;

import java.net.URI;
import java.net.URL;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.TimeUnit;

import org.forgerock.json.jose.exceptions.FailedToLoadJWKException;
import org.forgerock.json.jose.jwk.JWKSet;
import org.forgerock.json.jose.jws.JwsHeader;
import org.forgerock.json.jose.jws.SignedJwt;
import org.forgerock.json.jose.jwt.JwtClaimsSet;
import org.forgerock.util.promise.Promise;
import org.junit.jupiter.api.Test;

import com.forgerock.sapi.gateway.dcr.models.ApiClientTest;
import com.forgerock.sapi.gateway.dcr.models.ApiClient;
import com.forgerock.sapi.gateway.jwks.cache.BaseCachingJwkSetServiceTest.ReturnsErrorsJwkStore;
import com.forgerock.sapi.gateway.jwks.mocks.MockJwkSetService;
import com.forgerock.sapi.gateway.trusteddirectories.TrustedDirectory;
import com.forgerock.sapi.gateway.trusteddirectories.TrustedDirectoryOpenBankingTest;
import com.forgerock.sapi.gateway.trusteddirectories.TrustedDirectorySecureApiGateway;

class DefaultApiClientJwkSetServiceTest {

    @Test
    void fetchJwkSetFromJwksUri() throws Exception {
        final JWKSet jwkSet = createJwkSet();
        final URL jwksUri = new URL("https://directory.com/jwks/12345");
        final MockJwkSetService jwkSetService = new MockJwkSetService(Map.of(jwksUri, jwkSet));
        final ApiClientJwkSetService apiClientJwkSetService = new DefaultApiClientJwkSetService(jwkSetService);

        fetchJwkSetFromJwksUri(jwkSet, jwksUri, apiClientJwkSetService);
    }

    @Test
    void fetchJwkSetFromSoftwareStatement() throws Exception {
        // Never expect the JwkSetService to get called in this case
        final ReturnsErrorsJwkStore errorsJwkStore = new ReturnsErrorsJwkStore();
        final ApiClientJwkSetService apiClientJwkSetService = new DefaultApiClientJwkSetService(errorsJwkStore);
        fetchJwkSetFromSoftwareStatement(apiClientJwkSetService);
    }

    @Test
    void failsIfJwkSetServiceThrowsException() throws Exception {
        final URL jwksUri = new URL("https://directory.com/jwks/12345");
        final ApiClient apiClient = ApiClientTest.createApiClientWithJwksUri(jwksUri.toURI());
        final TrustedDirectory trustedDirectory = new TrustedDirectoryOpenBankingTest();

        // Returns an Exception promise on every call
        final JwkSetService errorsJwkStore = new ReturnsErrorsJwkStore();
        final ApiClientJwkSetService apiClientJwkSetService = new DefaultApiClientJwkSetService(errorsJwkStore);

        final Promise<JWKSet, FailedToLoadJWKException> jwkSetPromise = apiClientJwkSetService.getJwkSet(apiClient, trustedDirectory);
        final FailedToLoadJWKException exception = assertThrows(FailedToLoadJWKException.class,
                () -> jwkSetPromise.getOrThrow(1, TimeUnit.MILLISECONDS));
        assertEquals("getJwkSet failed", exception.getMessage());
    }

    @Test
    void failsIfJwksUriIsInvalid() throws Exception {
        final ApiClient apiClient = ApiClientTest.createApiClientWithJwksUri(new URI("foo://bar"));
        final TrustedDirectory trustedDirectory = new TrustedDirectoryOpenBankingTest();

        final JwkSetService errorsJwkStore = new ReturnsErrorsJwkStore();
        final ApiClientJwkSetService apiClientJwkSetService = new DefaultApiClientJwkSetService(errorsJwkStore);

        final Promise<JWKSet, FailedToLoadJWKException> jwkSetPromise = apiClientJwkSetService.getJwkSet(apiClient, trustedDirectory);
        final FailedToLoadJWKException exception = assertThrows(FailedToLoadJWKException.class,
                () -> jwkSetPromise.getOrThrow(1, TimeUnit.MILLISECONDS));
        assertEquals("Malformed jwksUri", exception.getMessage());
    }

    @Test
    void failsIfJwksUriIsNull() {
        final ApiClient apiClient = ApiClientTest.createBuilderWithJwks().build();
        final TrustedDirectory trustedDirectory = new TrustedDirectoryOpenBankingTest();

        final JwkSetService errorsJwkStore = new ReturnsErrorsJwkStore();
        final ApiClientJwkSetService apiClientJwkSetService = new DefaultApiClientJwkSetService(errorsJwkStore);

        final Promise<JWKSet, FailedToLoadJWKException> jwkSetPromise = apiClientJwkSetService.getJwkSet(apiClient, trustedDirectory);
        final Exception exception = assertThrows(FailedToLoadJWKException.class, () -> jwkSetPromise.getOrThrow(1, TimeUnit.MILLISECONDS));
        assertEquals("TrustedDirectory configuration requires the jwksUri to be set for the apiClient",
                     exception.getMessage());
    }

    @Test
    void failsToGetJwksFromSoftwareStatementIfTrustedDirectorySoftwareStatementJwksClaimNameIsMissing() throws Exception {
        final JwkSetService errorsJwkStore = new ReturnsErrorsJwkStore();
        final ApiClientJwkSetService apiClientJwkSetService = new DefaultApiClientJwkSetService(errorsJwkStore);
        final JWKSet jwkSet = createJwkSet();
        final URL secureApiGatewayJwksURI = new URL("https://blah.com");
        final TrustedDirectory misconfiguredDirectory = new TrustedDirectorySecureApiGateway(secureApiGatewayJwksURI) {
            @Override
            public String getSoftwareStatementJwksClaimName() {
                return null;
            }
        };
        final ApiClient apiClient = createApiClientWithSoftwareStatementJwks(jwkSet,"jwks");

        final Promise<JWKSet, FailedToLoadJWKException> jwkSetPromise = apiClientJwkSetService.getJwkSet(apiClient, misconfiguredDirectory);

        final Exception exception = assertThrows(FailedToLoadJWKException.class, () -> jwkSetPromise.getOrThrow(1, TimeUnit.MILLISECONDS));
        assertEquals("Trusted Directory has softwareStatemdntHoldsJwksUri=false but is missing softwareStatementJwksClaimName value",
                     exception.getMessage());
    }

    @Test
    void failsToGetJwksFromSoftwareStatementIfClaimIsNull() throws Exception {
        final ReturnsErrorsJwkStore errorsJwkStore = new ReturnsErrorsJwkStore();
        final ApiClientJwkSetService apiClientJwkSetService = new DefaultApiClientJwkSetService(errorsJwkStore);
        final JWKSet jwkSet = createJwkSet();
        final URL secureApiGatewayJwksURI = new URL("https://blah.com");
        final TrustedDirectory misconfiguredDirectory = new TrustedDirectorySecureApiGateway(secureApiGatewayJwksURI);
        final ApiClient apiClient = createApiClientWithSoftwareStatementJwks(jwkSet,null);

        final Promise<JWKSet, FailedToLoadJWKException> jwkSetPromise = apiClientJwkSetService.getJwkSet(apiClient, misconfiguredDirectory);

        final Exception exception = assertThrows(FailedToLoadJWKException.class, () -> jwkSetPromise.getOrThrow(1, TimeUnit.MILLISECONDS));
        assertEquals("SSA is missing claim: software_jwks which is expected to contain the JWKS",
                     exception.getMessage());
    }

    @Test
    void failsToGetJwksFromSoftwareStatementIfClaimsIsInvalidJwksJson() throws Exception {
        final ReturnsErrorsJwkStore errorsJwkStore = new ReturnsErrorsJwkStore();
        final ApiClientJwkSetService apiClientJwkSetService = new DefaultApiClientJwkSetService(errorsJwkStore);
        final URL secureApiGatewayJwksURI = new URL("https://blah.com");
        final TrustedDirectory misconfiguredDirectory = new TrustedDirectorySecureApiGateway(secureApiGatewayJwksURI);

        final JwtClaimsSet claimsSet = new JwtClaimsSet();
        claimsSet.setClaim(misconfiguredDirectory.getSoftwareStatementJwksClaimName(), json(object(field("keys", "should be a list"))));

        final ApiClient apiClient = ApiClientTest.createBuilderWithJwks().setSoftwareStatementAssertion(new SignedJwt(new JwsHeader(), claimsSet, new byte[0], new byte[0])).build();

        final Promise<JWKSet, FailedToLoadJWKException> jwkSetPromise = apiClientJwkSetService.getJwkSet(apiClient, misconfiguredDirectory);

        final Exception exception = assertThrows(FailedToLoadJWKException.class, () -> jwkSetPromise.getOrThrow(1, TimeUnit.MILLISECONDS));
        assertEquals("Invalid JWKS json at claim: software_jwks", exception.getMessage());
    }

    static JWKSet createJwkSet() {
        return new JWKSet(List.of(RestJwkSetServiceTest.createJWK(UUID.randomUUID().toString()),
                          RestJwkSetServiceTest.createJWK(UUID.randomUUID().toString())));
    }

    private void fetchJwkSetFromJwksUri(JWKSet expectedJwkSet, URL jwksUri, ApiClientJwkSetService apiClientJwkSetService) throws Exception {
        final ApiClient apiClient = ApiClientTest.createApiClientWithJwksUri(jwksUri.toURI());
        // OB Trusted Dir uses the jwksUri
        final TrustedDirectory trustedDirectory = new TrustedDirectoryOpenBankingTest();
        invokeFilterAndValidateSuccessResponse(expectedJwkSet, apiClient, trustedDirectory, apiClientJwkSetService);
    }

    private void fetchJwkSetFromSoftwareStatement(ApiClientJwkSetService apiClientJwkSetService) throws Exception {
        final JWKSet jwkSet = createJwkSet();
        // SAPI-G directory uses the software statement jwks
        final URL secureApiGatewayJwksURI = new URL("https://blah.com");
        final TrustedDirectory trustedDirectory = new TrustedDirectorySecureApiGateway(secureApiGatewayJwksURI);
        final ApiClient apiClient = createApiClientWithSoftwareStatementJwks(jwkSet, trustedDirectory.getSoftwareStatementJwksClaimName());

        invokeFilterAndValidateSuccessResponse(jwkSet, apiClient, trustedDirectory, apiClientJwkSetService);
    }

    private void invokeFilterAndValidateSuccessResponse(JWKSet expectedJwkSet, ApiClient apiClient,
                                                        TrustedDirectory trustedDirectory,
                                                        ApiClientJwkSetService apiClientJwkSetService) throws Exception {

        final Promise<JWKSet, FailedToLoadJWKException> jwkSetPromise = apiClientJwkSetService.getJwkSet(apiClient, trustedDirectory);
        final JWKSet jwkSet = jwkSetPromise.get(1, TimeUnit.MILLISECONDS);
        assertEquals(expectedJwkSet, jwkSet);
    }
}