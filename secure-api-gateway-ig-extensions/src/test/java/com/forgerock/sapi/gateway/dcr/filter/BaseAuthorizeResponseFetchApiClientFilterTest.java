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

import static com.forgerock.sapi.gateway.dcr.filter.FetchApiClientFilterTest.createApiClientService;
import static com.forgerock.sapi.gateway.dcr.service.idm.IdmApiClientDecoderTest.createIdmApiClientWithJwks;
import static com.forgerock.sapi.gateway.dcr.service.idm.IdmApiClientDecoderTest.verifyIdmClientDataMatchesApiClientObject;
import static org.assertj.core.api.Assertions.assertThat;
import static org.forgerock.json.JsonValue.json;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.function.BiConsumer;
import java.util.function.Function;

import org.forgerock.http.Client;
import org.forgerock.http.Handler;
import org.forgerock.http.protocol.Request;
import org.forgerock.http.protocol.Response;
import org.forgerock.http.protocol.Status;
import org.forgerock.json.JsonValue;
import org.forgerock.openig.handler.Handlers;
import org.forgerock.services.context.AttributesContext;
import org.forgerock.services.context.RootContext;
import org.forgerock.util.promise.NeverThrowsException;
import org.forgerock.util.promise.Promise;
import org.junit.jupiter.api.Test;

import com.forgerock.sapi.gateway.dcr.models.ApiClient;
import com.forgerock.sapi.gateway.dcr.service.idm.IdmApiClientServiceTest.MockGetApiClientIdmHandler;
import com.forgerock.sapi.gateway.util.TestHandlers.FixedResponseHandler;
import com.forgerock.sapi.gateway.util.TestHandlers.TestSuccessResponseHandler;

public abstract class BaseAuthorizeResponseFetchApiClientFilterTest {
    static final String idmBaseUri = "http://localhost/openidm/managed";
    static final String clientId = "9999";
    private static AttributesContext createContext() {
        return new AttributesContext(new RootContext("root"));
    }

    protected AuthorizeResponseFetchApiClientFilter createFilter(Handler idmResponseHandler) {
        return new AuthorizeResponseFetchApiClientFilter(createApiClientService(new Client(idmResponseHandler), idmBaseUri),
                                                         createClientIdRetriever());
    }

    protected abstract Function<Request, Promise<String, NeverThrowsException>> createClientIdRetriever();

    @Test
    void fetchApiClientForSuccessResponse() throws Exception {
        final JsonValue idmClientData = createIdmApiClientWithJwks(clientId);
        final MockGetApiClientIdmHandler idmResponseHandler = new MockGetApiClientIdmHandler(idmBaseUri, clientId, idmClientData);
        callFilterValidateSuccessBehaviour(idmClientData, createFilter(idmResponseHandler));
    }

    protected void callFilterValidateSuccessBehaviour(JsonValue idmClientData, AuthorizeResponseFetchApiClientFilter filter) throws Exception {

        final BiConsumer<Response, AttributesContext> successBehaviourValidator = (response, ctxt) -> {
            // Verify we hit the end of the chain and got the NO_CONTENT response
            assertEquals(Status.NO_CONTENT, response.getStatus());

            // Verify that the context was updated with the apiClient data
            final ApiClient apiClient = FetchApiClientFilter.getApiClientFromContext(ctxt);
            assertNotNull(apiClient, "apiClient was not found in context");
            verifyIdmClientDataMatchesApiClientObject(idmClientData, apiClient);
        };
        callFilter(filter, successBehaviourValidator);
    }

    private void callFilter(AuthorizeResponseFetchApiClientFilter filter, BiConsumer<Response, AttributesContext> responseAndContextValidator) throws Exception {
        final AttributesContext attributesContext = BaseAuthorizeResponseFetchApiClientFilterTest.createContext();

        // This is the next handler called after the AuthoriseResponseFetchApiClientFilter
        final Handler endOfFilterChainHandler = Handlers.NO_CONTENT;
        final Request request = createRequest();
        final Promise<Response, NeverThrowsException> responsePromise = filter.filter(attributesContext, request, endOfFilterChainHandler);

        final Response response = responsePromise.getOrThrow(1L, TimeUnit.SECONDS);

        // Do the validation
        responseAndContextValidator.accept(response, attributesContext);
    }

    protected abstract Request createRequest();

    @Test
    void doesNotFetchApiClientForErrorResponses() throws InterruptedException, TimeoutException {
        final JsonValue idmClientData = createIdmApiClientWithJwks(clientId);
        final MockGetApiClientIdmHandler idmResponseHandler = new MockGetApiClientIdmHandler(idmBaseUri, clientId, idmClientData);
        final AuthorizeResponseFetchApiClientFilter filter = createFilter(idmResponseHandler);
        final AttributesContext context = BaseAuthorizeResponseFetchApiClientFilterTest.createContext();

        final Promise<Response, NeverThrowsException> responsePromise = filter.filter(context, createRequest(), new FixedResponseHandler(new Response(Status.BAD_GATEWAY)));
        final Response response = responsePromise.getOrThrow(1, TimeUnit.SECONDS);

        assertThat(response.getStatus()).isEqualTo(Status.BAD_GATEWAY);
        assertThat(FetchApiClientFilter.getApiClientFromContext(context)).isNull();
    }

    @Test
    void returnsErrorResponseWhenClientIdParamNotFound() throws Exception {
        final JsonValue idmClientData = createIdmApiClientWithJwks(clientId);
        final MockGetApiClientIdmHandler idmResponseHandler = new MockGetApiClientIdmHandler(idmBaseUri, clientId, idmClientData);
        final AuthorizeResponseFetchApiClientFilter filter = createFilter(idmResponseHandler);
        final AttributesContext context = BaseAuthorizeResponseFetchApiClientFilterTest.createContext();

        final Request request = new Request();
        request.setUri("/authorize");
        final Promise<Response, NeverThrowsException> responsePromise = filter.filter(context, request, new TestSuccessResponseHandler());
        final Response response = responsePromise.getOrThrow(1, TimeUnit.SECONDS);

        assertThat(response.getStatus()).isEqualTo(Status.BAD_REQUEST);
        final JsonValue json = json(response.getEntity().getJson());
        assertThat(json.get("error").asString()).isEqualTo("invalid_request");
        assertThat(json.get("error_description").asString()).isEqualTo("'client_id' is missing in the request.");
        assertThat(FetchApiClientFilter.getApiClientFromContext(context)).isNull();
    }

    @Test
    void returnsErrorResponseWhenApiClientServiceReturnsException() throws Exception {
        final AuthorizeResponseFetchApiClientFilter filter = createFilter(Handlers.INTERNAL_SERVER_ERROR);
        final AttributesContext context = BaseAuthorizeResponseFetchApiClientFilterTest.createContext();

        final Promise<Response, NeverThrowsException> responsePromise = filter.filter(context, createRequest(), new TestSuccessResponseHandler());
        final Response response = responsePromise.getOrThrow(1, TimeUnit.SECONDS);

        assertThat(response.getStatus()).isEqualTo(Status.INTERNAL_SERVER_ERROR);
        assertThat(FetchApiClientFilter.getApiClientFromContext(context)).isNull();
    }
}
