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
package com.forgerock.sapi.gateway.dcr.filter;

import static com.forgerock.sapi.gateway.dcr.service.idm.IdmApiClientDecoderTest.createIdmApiClientWithJwks;
import static com.forgerock.sapi.gateway.dcr.service.idm.IdmApiClientDecoderTest.verifyIdmClientDataMatchesApiClientObject;
import static org.forgerock.json.JsonValue.field;
import static org.forgerock.json.JsonValue.json;
import static org.forgerock.json.JsonValue.object;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.Set;
import java.util.concurrent.TimeUnit;
import java.util.function.BiConsumer;

import org.forgerock.http.Client;
import org.forgerock.http.Handler;
import org.forgerock.http.oauth2.AccessTokenInfo;
import org.forgerock.http.oauth2.OAuth2Context;
import org.forgerock.http.protocol.Request;
import org.forgerock.http.protocol.Response;
import org.forgerock.http.protocol.Status;
import org.forgerock.json.JsonValue;
import org.forgerock.openig.handler.Handlers;
import org.forgerock.openig.heap.HeapException;
import org.forgerock.openig.heap.HeapImpl;
import org.forgerock.openig.heap.Name;
import org.forgerock.services.context.AttributesContext;
import org.forgerock.services.context.RootContext;
import org.forgerock.util.promise.NeverThrowsException;
import org.forgerock.util.promise.Promise;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import com.forgerock.sapi.gateway.dcr.filter.FetchApiClientFilter.Heaplet;
import com.forgerock.sapi.gateway.dcr.models.ApiClient;
import com.forgerock.sapi.gateway.dcr.service.ApiClientService;
import com.forgerock.sapi.gateway.dcr.service.idm.IdmApiClientDecoder;
import com.forgerock.sapi.gateway.dcr.service.idm.IdmApiClientDecoderTest;
import com.forgerock.sapi.gateway.dcr.service.idm.IdmApiClientService;
import com.forgerock.sapi.gateway.dcr.service.idm.IdmApiClientServiceTest.MockGetApiClientIdmHandler;

/**
 * Unit tests for {@link FetchApiClientFilter}.
 * <p>
 * IDM behaviour is simulated using Handlers installed as the httpClient within the Filter.
 * See {@link MockGetApiClientIdmHandler} for an example Handler which returns mocked ApiClient data.
 */
class FetchApiClientFilterTest {

    @Test
    void fetchApiClientUsingMockedIdmResponseWithAllFields() throws Exception {
        final String clientId = "1234-5678-9101";
        final JsonValue idmClientData = IdmApiClientDecoderTest.createIdmApiClientWithJwksUri(clientId);
        testFetchingApiClient(clientId, idmClientData);
    }

    @Test
    void fetchApiClientUsingMockedIdmResponseWithMandatoryFieldsOnly() throws Exception {
        final String clientId = "9999";
        final JsonValue idmClientData = createIdmApiClientWithJwks(clientId);
        testFetchingApiClient(clientId, idmClientData);
    }

    private static void testFetchingApiClient(String clientId, JsonValue idmClientData) throws Exception {
        final MockGetApiClientIdmHandler idmResponseHandler = new MockGetApiClientIdmHandler("http://localhost/openidm/managed", clientId, idmClientData);
        final String clientIdClaim = "aud";
        final AccessTokenInfo accessToken = createAccessToken(clientIdClaim, clientId);
        final FetchApiClientFilter filter = new FetchApiClientFilter(createApiClientService(new Client(idmResponseHandler), "http://localhost/openidm/managed"), clientIdClaim);
        callFilterValidateSuccessBehaviour(accessToken, idmClientData, filter);
    }

    public static ApiClientService createApiClientService(Client client, String idmBaseUri) {
        return new IdmApiClientService(client, idmBaseUri, new IdmApiClientDecoder());
    }

    @Test
    void failsWhenNoOAuth2ContextIsFound() {
        final FetchApiClientFilter filter = new FetchApiClientFilter(createApiClientService(new Client(Handlers.FORBIDDEN), "notUsed"), "aud");
        assertThrows(IllegalArgumentException.class, () -> filter.filter(new RootContext("root"), new Request(), Handlers.FORBIDDEN),
                "No context of type org.forgerock.http.oauth2.OAuth2Context found");
    }

    @Test
    void returnsErrorResponseWhenUnableToDetermineClientId() throws Exception{
        final FetchApiClientFilter filter = new FetchApiClientFilter(createApiClientService(new Client(Handlers.FORBIDDEN), "notUsed"), "aud");
        final AccessTokenInfo accessTokenWithoutAudClaim = new AccessTokenInfo(json(object()), "token", Set.of("scope1"), 0L);
        final Promise<Response, NeverThrowsException> responsePromise = filter.filter(new OAuth2Context(new RootContext("root"), accessTokenWithoutAudClaim), new Request(), Handlers.FORBIDDEN);

        final Response response = responsePromise.get(1, TimeUnit.SECONDS);
        assertEquals(Status.INTERNAL_SERVER_ERROR, response.getStatus());
    }

    @Test
    void returnsErrorResponseWhenApiClientServiceReturnsException() throws Exception {
        // Mock IDM returning 500 response
        final String clientIdClaim = "client_id";
        final FetchApiClientFilter filter = new FetchApiClientFilter(createApiClientService(new Client(Handlers.INTERNAL_SERVER_ERROR), "http://localhost/openidm"), clientIdClaim);
        final OAuth2Context context = new OAuth2Context(new RootContext("root"), createAccessToken(clientIdClaim, "1234"));
        final Promise<Response, NeverThrowsException> responsePromise = filter.filter(context, new Request(), Handlers.FORBIDDEN);

        final Response response = responsePromise.get(1, TimeUnit.SECONDS);
        assertEquals(Status.INTERNAL_SERVER_ERROR, response.getStatus());
    }

    @Nested
    class HeapletTests {
        @Test
        void failsToConstructIfApiClientServiceIsMissing() {
            final HeapException heapException = assertThrows(HeapException.class, () -> new Heaplet().create(Name.of("test"),
                    json(object()), new HeapImpl(Name.of("heap"))), "Invalid object declaration");
            assertEquals(heapException.getCause().getMessage(), "/apiClientService: Expecting a value");
        }

        @Test
        void successfullyCreatesFilterWithRequiredConfigOnly() throws Exception {
            final String idmBaseUri = "http://idm/managed";
            final String clientId = "999999999";
            final JsonValue idmApiClientData = IdmApiClientDecoderTest.createIdmApiClientWithJwksUri(clientId);
            final Handler idmClientHandler = new MockGetApiClientIdmHandler(idmBaseUri, clientId, idmApiClientData);

            final HeapImpl heap = new HeapImpl(Name.of("heap"));
            heap.put("IdmApiClientService", new IdmApiClientService(new Client(idmClientHandler), idmBaseUri, new IdmApiClientDecoder()));

            final JsonValue config = json(object(field("apiClientService", "IdmApiClientService")));
            final FetchApiClientFilter filter = (FetchApiClientFilter) new Heaplet().create(Name.of("test"), config, heap);


            // optional config: accessTokenClientIdClaim will be defaulted to aud
            final AccessTokenInfo accessToken = createAccessToken("aud", clientId);
            // Test the filter created by the Heaplet
            callFilterValidateSuccessBehaviour(accessToken, idmApiClientData, filter);
        }

        @Test
        void successfullyCreatesFilterWithAllOptionalConfigSupplied() throws Exception {
            final String idmBaseUri = "http://idm/managed";
            final String clientId = "999999999";
            final JsonValue idmApiClientData = IdmApiClientDecoderTest.createIdmApiClientWithJwksUri(clientId);
            final Handler idmClientHandler = new MockGetApiClientIdmHandler(idmBaseUri, clientId, idmApiClientData);

            final HeapImpl heap = new HeapImpl(Name.of("heap"));
            heap.put("IdmApiClientService", new IdmApiClientService(new Client(idmClientHandler), idmBaseUri, new IdmApiClientDecoder()));

            final String clientIdClaim = "client_id";
            final JsonValue config = json(object(field("apiClientService", "IdmApiClientService"),
                                                 field("accessTokenClientIdClaim", clientIdClaim)));
            final FetchApiClientFilter filter = (FetchApiClientFilter) new Heaplet().create(Name.of("test"), config, heap);

            final AccessTokenInfo accessToken = createAccessToken(clientIdClaim, clientId);
            // Test the filter created by the Heaplet
            callFilterValidateSuccessBehaviour(accessToken, IdmApiClientDecoderTest.createIdmApiClientWithJwksUri(clientId), filter);
        }
    }

    private static void callFilterValidateSuccessBehaviour(AccessTokenInfo accessToken, JsonValue idmClientData,
                                                          FetchApiClientFilter filter) throws Exception {

        final BiConsumer<Response, AttributesContext> successBehaviourValidator = (response, ctxt) -> {
            // Verify we hit the end of the chain and got the NO_CONTENT response
            assertEquals(Status.NO_CONTENT, response.getStatus());

            // Verify that the context was updated with the apiClient data
            final ApiClient apiClient = FetchApiClientFilter.getApiClientFromContext(ctxt);
            assertNotNull(apiClient, "apiClient was not found in context");
            verifyIdmClientDataMatchesApiClientObject(idmClientData, apiClient);
        };
        callFilter(accessToken, filter, successBehaviourValidator);
    }

    private static void callFilter(AccessTokenInfo accessToken, FetchApiClientFilter filter,
                                   BiConsumer<Response, AttributesContext> responseAndContextValidator) throws Exception {
        final AttributesContext attributesContext = new AttributesContext(new RootContext("root"));
        final OAuth2Context oauth2Context = new OAuth2Context(attributesContext, accessToken);

        // This is the next handler called after the FetchApiClientFilter
        final Handler endOfFilterChainHandler = Handlers.NO_CONTENT;
        final Promise<Response, NeverThrowsException> responsePromise = filter.filter(oauth2Context, new Request(), endOfFilterChainHandler);

        final Response response = responsePromise.get(1L, TimeUnit.SECONDS);

        // Do the validation
        responseAndContextValidator.accept(response, attributesContext);
    }

    private static AccessTokenInfo createAccessToken(String clientIdClaim, String clientId) {
        return new AccessTokenInfo(json(object(field(clientIdClaim, clientId))), "token", Set.of("scope1"), 0L);
    }
}