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
package com.forgerock.sapi.gateway.trusteddirectories;

import static org.assertj.core.api.Assertions.assertThat;
import static org.forgerock.json.JsonValue.field;
import static org.forgerock.json.JsonValue.json;
import static org.forgerock.json.JsonValue.object;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.net.URI;

import org.forgerock.http.protocol.Request;
import org.forgerock.json.JsonValue;
import org.forgerock.json.jose.jws.JwsHeader;
import org.forgerock.json.jose.jws.SignedJwt;
import org.forgerock.json.jose.jwt.JwtClaimsSet;
import org.forgerock.openig.heap.HeapException;
import org.forgerock.openig.heap.HeapImpl;
import org.forgerock.openig.heap.Name;
import org.forgerock.services.context.AttributesContext;
import org.forgerock.services.context.Context;
import org.forgerock.services.context.RootContext;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import com.forgerock.sapi.gateway.dcr.filter.FetchApiClientFilter;
import com.forgerock.sapi.gateway.dcr.models.ApiClient;
import com.forgerock.sapi.gateway.dcr.models.ApiClientTest;
import com.forgerock.sapi.gateway.trusteddirectories.FetchTrustedDirectoryFilter.Heaplet;
import com.forgerock.sapi.gateway.util.TestHandlers.TestSuccessResponseHandler;

public class FetchTrustedDirectoryFilterTest {

    private TrustedDirectoryService trustedDirectoryService;

    @BeforeEach
    void setUp() {
        URI secureApiGatewayJwksUri = URI.create("https://test-bank.com");
        trustedDirectoryService = new TrustedDirectoryServiceStatic(true, secureApiGatewayJwksUri);
    }

    public static ApiClient createApiClient(String issuer) {
        final JwtClaimsSet ssaClaims = new JwtClaimsSet();
        ssaClaims.setIssuer(issuer);
        final SignedJwt ssaSignedJwt = new SignedJwt(new JwsHeader(), ssaClaims, new byte[0], new byte[0]);

        return ApiClientTest.createBuilderWithJwks().setSoftwareStatementAssertion(ssaSignedJwt).build();
    }

    @Test
    void testTrustedDirectoryIsAddedToContext() {
        final FetchTrustedDirectoryFilter filter = new FetchTrustedDirectoryFilter(trustedDirectoryService);
        testFetchingOpenBankingTestIssuer(filter);
    }

    private void testFetchingOpenBankingTestIssuer(FetchTrustedDirectoryFilter filter) {
        final Context rootContext = new RootContext("root");
        final AttributesContext attributesContext = new AttributesContext(rootContext);
        final ApiClient apiClient = createApiClient(TrustedDirectoryOpenBankingTest.issuer);
        attributesContext.getAttributes().put(FetchApiClientFilter.API_CLIENT_ATTR_KEY, apiClient);

        callFilterAndValidateSuccessResponse(filter, attributesContext);
    }

    @Test
    void failsIfApiClientNotFound() {
        final IllegalStateException exception = assertThrows(IllegalStateException.class,
                () -> callFilterAndValidateSuccessResponse(new FetchTrustedDirectoryFilter(trustedDirectoryService), new AttributesContext(new RootContext("root"))));

        assertThat(exception.getMessage()).contains("apiClient not found in request context");
    }

    @Test
    void failsIfTrustedDirectoryDoesNotExistForIssuer() {
        final Context rootContext = new RootContext("root");
        final AttributesContext attributesContext = new AttributesContext(rootContext);
        final ApiClient apiClient = createApiClient("ACME Bank");
        attributesContext.getAttributes().put(FetchApiClientFilter.API_CLIENT_ATTR_KEY, apiClient);

        final IllegalStateException exception = assertThrows(IllegalStateException.class,
                () -> callFilterAndValidateSuccessResponse(new FetchTrustedDirectoryFilter(trustedDirectoryService), attributesContext));

        assertThat(exception.getMessage()).contains("Failed to get trusted directory for apiClient");
    }

    @Nested
    class HeapletTests {
        @Test
        void testFilterCreatedByHeaplet() throws Exception {
            final HeapImpl heap = new HeapImpl(Name.of("heap"));
            heap.put("trustedDirectoryService", trustedDirectoryService);

            final JsonValue config = json(object(field("trustedDirectoryService", "trustedDirectoryService")));
            final FetchTrustedDirectoryFilter filter = (FetchTrustedDirectoryFilter) new Heaplet().create(Name.of("test"), config, heap);
            testFetchingOpenBankingTestIssuer(filter);
        }

        @Test
        void failToCreateFilterWhenTrustedDirectoryConfigIsMissing() {
            final HeapImpl heap = new HeapImpl(Name.of("heap"));
            final JsonValue config = json(object());
            final HeapException heapException = assertThrows(HeapException.class, () -> new Heaplet().create(Name.of("test"), config, heap));
            assertEquals("/trustedDirectoryService: Expecting a value", heapException.getCause().getMessage());
        }
    }

    private void callFilterAndValidateSuccessResponse(FetchTrustedDirectoryFilter filter, Context context) {
        assertNull(FetchTrustedDirectoryFilter.getTrustedDirectoryFromContext(context),
                "There must be no TrustedDirectory in the context prior to the test running");

        final TestSuccessResponseHandler successResponseHandler = new TestSuccessResponseHandler();
        filter.filter(context, new Request(), successResponseHandler);

        final TrustedDirectory trustedDirectory = FetchTrustedDirectoryFilter.getTrustedDirectoryFromContext(context);
        assertEquals(TrustedDirectoryOpenBankingTest.issuer, trustedDirectory.getIssuer());
        assertTrue(successResponseHandler.hasBeenInteractedWith(), "Expected filter to pass request on to the successResponseHandler");
    }
}