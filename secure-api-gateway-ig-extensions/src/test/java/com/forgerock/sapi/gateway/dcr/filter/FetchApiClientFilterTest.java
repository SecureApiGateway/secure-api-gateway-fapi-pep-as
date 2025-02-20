/*
 * Copyright © 2020-2025 ForgeRock AS (obst@forgerock.com)
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

import static com.forgerock.sapi.gateway.util.JsonUtils.assertJsonEquals;
import static org.assertj.core.api.Assertions.assertThat;
import static org.forgerock.json.JsonValue.field;
import static org.forgerock.json.JsonValue.json;
import static org.forgerock.json.JsonValue.object;
import static org.forgerock.util.promise.Promises.newExceptionPromise;
import static org.forgerock.util.promise.Promises.newResultPromise;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.when;

import java.io.IOException;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import java.util.function.BiConsumer;

import org.forgerock.http.Handler;
import org.forgerock.http.oauth2.AccessTokenInfo;
import org.forgerock.http.oauth2.OAuth2Context;
import org.forgerock.http.protocol.Request;
import org.forgerock.http.protocol.Response;
import org.forgerock.http.protocol.Status;
import org.forgerock.json.JsonValue;
import org.forgerock.openig.fapi.apiclient.ApiClient;
import org.forgerock.openig.fapi.apiclient.service.ApiClientService;
import org.forgerock.openig.fapi.apiclient.service.ApiClientServiceException;
import org.forgerock.openig.fapi.apiclient.service.ApiClientServiceException.ErrorCode;
import org.forgerock.openig.handler.Handlers;
import org.forgerock.openig.heap.HeapException;
import org.forgerock.openig.heap.HeapImpl;
import org.forgerock.openig.heap.Name;
import org.forgerock.services.context.AttributesContext;
import org.forgerock.services.context.RootContext;
import org.forgerock.util.promise.NeverThrowsException;
import org.forgerock.util.promise.Promise;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import com.forgerock.sapi.gateway.dcr.filter.FetchApiClientFilter.Heaplet;

/**
 * Unit tests for {@link FetchApiClientFilter}.
 */
@ExtendWith(MockitoExtension.class)
class FetchApiClientFilterTest {

    private static final String DEFAULT_CLIENT_ID_CLAIM = "aud";

    private static final String CLIENT_ID = "1234-5678-9101";

    @Mock
    private ApiClientService apiClientService;

    @Mock
    private ApiClient testApiClient;

    private FetchApiClientFilter filter;

    @BeforeEach
    void beforeEach() {
        this.filter = new FetchApiClientFilter(apiClientService, DEFAULT_CLIENT_ID_CLAIM);
    }

    @Test
    void shouldFetchApiClientUsingOAuth2ClientId() throws Exception {
        callFilterValidateSuccessBehaviour(filter);
    }

    private void callFilterValidateSuccessBehaviour(FetchApiClientFilter filter) throws Exception {
        callFilterValidateSuccessBehaviour(filter, DEFAULT_CLIENT_ID_CLAIM);
    }

    private void callFilterValidateSuccessBehaviour(FetchApiClientFilter filter, String clientIdClaim) throws Exception {
        final AccessTokenInfo accessToken = createAccessToken(clientIdClaim, CLIENT_ID);

        // Mock the success response for the ApiClientService call
        when(apiClientService.get(any(), eq(CLIENT_ID))).thenReturn(newResultPromise(testApiClient));

        final BiConsumer<Response, AttributesContext> successBehaviourValidator = (response, ctxt) -> {
            // Verify we hit the end of the chain and got the NO_CONTENT response
            assertEquals(Status.NO_CONTENT, response.getStatus());

            // Verify that the context was updated with the testApiClient data
            final ApiClient apiClient = FetchApiClientFilter.getApiClientFromContext(ctxt);
            assertNotNull(apiClient, "apiClient was not found in context");
            assertThat(apiClient).isSameAs(testApiClient);
        };
        callFilter(accessToken, filter, successBehaviourValidator);
    }

    private static AccessTokenInfo createAccessToken(String clientIdClaim, String clientId) {
        return new AccessTokenInfo(json(object(field(clientIdClaim, clientId))), "token", Set.of("scope1"), 0L);
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

    @Test
    void failsWhenNoOAuth2ContextIsFound() {
        final RootContext context = new RootContext("root");
        assertThrows(IllegalArgumentException.class,
                     () -> filter.filter(context, new Request(), Handlers.FORBIDDEN),
                     "No context of type org.forgerock.http.oauth2.OAuth2Context found");
    }

    @Test
    void returnsErrorResponseWhenUnableToDetermineClientId() throws Exception{
        final AccessTokenInfo accessTokenWithoutAudClaim = new AccessTokenInfo(json(object()), "token", Set.of("scope1"), 0L);
        final OAuth2Context context = new OAuth2Context(new RootContext("root"), accessTokenWithoutAudClaim);

        final Promise<Response, NeverThrowsException> responsePromise = filter.filter(context, new Request(), Handlers.FORBIDDEN);

        final Response response = responsePromise.get(1, TimeUnit.SECONDS);
        assertEquals(Status.INTERNAL_SERVER_ERROR, response.getStatus());
    }

    @ParameterizedTest
    @EnumSource(value = ErrorCode.class, names = {"NOT_FOUND", "DELETED"})
    void returnsErrorResponseWhenApiClientIsNotFound(ErrorCode errorCode) throws Exception{
        // Mock error response from ApiClientService
        when(apiClientService.get(any(), eq(CLIENT_ID))).thenReturn(
                newExceptionPromise(new ApiClientServiceException(errorCode,
                                                                  "ApiClient " + CLIENT_ID + " does not exist")));

        final AccessTokenInfo accessToken = createAccessToken(DEFAULT_CLIENT_ID_CLAIM, CLIENT_ID);
        final OAuth2Context context = new OAuth2Context(new RootContext("root"), accessToken);

        final Promise<Response, NeverThrowsException> responsePromise = filter.filter(context, new Request(), Handlers.FORBIDDEN);

        final Response response = responsePromise.get(1, TimeUnit.SECONDS);
        assertEquals(Status.UNAUTHORIZED, response.getStatus());
        try {
            assertJsonEquals(json(object(field("error", "client registration is invalid"))),
                             json(response.getEntity().getJson()));
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    @Test
    void returnsErrorResponseWhenApiClientServiceReturnsUnexpectedException() throws Exception {
        // Mock unexpected error response from ApiClientService
        when(apiClientService.get(any(), eq(CLIENT_ID))).thenReturn(
                newExceptionPromise(new ApiClientServiceException(ErrorCode.SERVER_ERROR, "Unexpected error")));

        final AccessTokenInfo accessToken = createAccessToken(DEFAULT_CLIENT_ID_CLAIM, CLIENT_ID);
        final OAuth2Context context = new OAuth2Context(new RootContext("root"), accessToken);

        final Promise<Response, NeverThrowsException> responsePromise = filter.filter(context, new Request(), Handlers.FORBIDDEN);

        final Response response = responsePromise.get(1, TimeUnit.SECONDS);
        assertEquals(Status.INTERNAL_SERVER_ERROR, response.getStatus());
    }

    @Nested
    class HeapletTests {
        @Test
        void failsToConstructIfApiClientServiceIsMissing() {
            final HeapException heapException = assertThrows(HeapException.class,
                                                             () -> new Heaplet().create(Name.of("test"),
                                                                                        json(object()),
                                                                                        new HeapImpl(Name.of("heap"))),
                                                             "Invalid object declaration");
            assertEquals(heapException.getCause().getMessage(), "/apiClientService: Expecting a value");
        }

        @Test
        void successfullyCreatesFilterWithRequiredConfigOnly() throws Exception {
            final HeapImpl heap = new HeapImpl(Name.of("heap"));
            heap.put("IdmApiClientService", apiClientService);

            // Only configure apiClientService, the accessTokenClientIdClaim will be defaulted to aud
            final JsonValue config = json(object(field("apiClientService", "IdmApiClientService")));
            final FetchApiClientFilter filter = (FetchApiClientFilter) new Heaplet().create(Name.of("test"),
                                                                                            config,
                                                                                            heap);

            // Test the filter created by the Heaplet
            callFilterValidateSuccessBehaviour(filter);
        }

        @Test
        void successfullyCreatesFilterWithAllOptionalConfigSupplied() throws Exception {
            final HeapImpl heap = new HeapImpl(Name.of("heap"));
            heap.put("IdmApiClientService", apiClientService);

            // Supply a custom clientIdClaim value
            final String clientIdClaim = "client_id";
            final JsonValue config = json(object(field("apiClientService", "IdmApiClientService"),
                                                 field("accessTokenClientIdClaim", clientIdClaim)));

            final FetchApiClientFilter filter = (FetchApiClientFilter) new Heaplet().create(Name.of("test"),
                                                                                            config,
                                                                                            heap);

            // Test the filter created by the Heaplet
            callFilterValidateSuccessBehaviour(filter, clientIdClaim);
        }
    }


}