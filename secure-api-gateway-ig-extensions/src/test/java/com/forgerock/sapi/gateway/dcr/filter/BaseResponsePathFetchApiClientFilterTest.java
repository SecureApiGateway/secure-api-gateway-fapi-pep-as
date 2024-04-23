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
import static org.junit.jupiter.api.Assertions.assertNotNull;

import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.function.Consumer;

import org.forgerock.http.Client;
import org.forgerock.http.Filter;
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
import com.forgerock.sapi.gateway.dcr.service.ApiClientService;
import com.forgerock.sapi.gateway.dcr.service.idm.IdmApiClientServiceTest.MockGetApiClientIdmHandler;
import com.forgerock.sapi.gateway.util.TestHandlers.FixedResponseHandler;

public abstract class BaseResponsePathFetchApiClientFilterTest {
    static final String idmBaseUri = "http://localhost/openidm/managed";
    static final String clientId = "9999";
    private static AttributesContext createContext() {
        return new AttributesContext(new RootContext("root"));
    }

    protected Filter createFilter(Handler idmResponseHandler) {
        return createFilter(createApiClientService(new Client(idmResponseHandler), idmBaseUri));
    }

    protected abstract Filter createFilter(ApiClientService apiClientService);

    @Test
    void fetchApiClientForSuccessResponse() throws Exception {
        final JsonValue idmClientData = createIdmApiClientWithJwks(clientId);
        final MockGetApiClientIdmHandler idmResponseHandler = new MockGetApiClientIdmHandler(idmBaseUri, clientId, idmClientData);
        callFilterValidateSuccessBehaviour(idmClientData, createFilter(idmResponseHandler));
    }

    protected void callFilterValidateSuccessBehaviour(JsonValue idmClientData, Filter filter) throws Exception {
        final Consumer<AttributesContext> successBehaviourValidator = ctxt -> {
            // Verify that the context was updated with the apiClient data
            final ApiClient apiClient = FetchApiClientFilter.getApiClientFromContext(ctxt);
            assertNotNull(apiClient, "apiClient was not found in context");
            verifyIdmClientDataMatchesApiClientObject(idmClientData, apiClient);
        };
        callFilter(filter, successBehaviourValidator);
    }

    private void callFilter(Filter filter, Consumer<AttributesContext> contextValidator) throws Exception {
        final AttributesContext attributesContext = BaseResponsePathFetchApiClientFilterTest.createContext();

        final Response upstreamResponse = createValidUpstreamResponse();
        final FixedResponseHandler upstreamHandler = new FixedResponseHandler(upstreamResponse);
        final Request request = createRequest();
        final Promise<Response, NeverThrowsException> responsePromise = filter.filter(attributesContext, request, upstreamHandler);

        final Response response = responsePromise.getOrThrow(1L, TimeUnit.SECONDS);
        // Validate the filter returns the upstream response unaltered on success paths
        assertThat(response).isEqualTo(upstreamResponse);

        // Validate the context
        contextValidator.accept(attributesContext);
    }

    protected abstract Request createRequest();

    protected abstract Response createValidUpstreamResponse();

    @Test
    void doesNotFetchApiClientForErrorResponses() throws InterruptedException, TimeoutException {
        final JsonValue idmClientData = createIdmApiClientWithJwks(clientId);
        final MockGetApiClientIdmHandler idmResponseHandler = new MockGetApiClientIdmHandler(idmBaseUri, clientId, idmClientData);
        final Filter filter = createFilter(idmResponseHandler);
        final AttributesContext context = BaseResponsePathFetchApiClientFilterTest.createContext();

        final Promise<Response, NeverThrowsException> responsePromise = filter.filter(context, createRequest(),
                new FixedResponseHandler(new Response(Status.BAD_GATEWAY)));

        final Response response = responsePromise.getOrThrow(1, TimeUnit.SECONDS);

        assertThat(response.getStatus()).isEqualTo(Status.BAD_GATEWAY);
        assertThat(FetchApiClientFilter.getApiClientFromContext(context)).isNull();
    }

    void returnsErrorResponseWhenClientIdParamNotFound(Request request, Response upstreamResponse) throws Exception {
        final JsonValue idmClientData = createIdmApiClientWithJwks(clientId);
        final MockGetApiClientIdmHandler idmResponseHandler = new MockGetApiClientIdmHandler(idmBaseUri, clientId, idmClientData);
        final Filter filter = createFilter(idmResponseHandler);
        final AttributesContext context = BaseResponsePathFetchApiClientFilterTest.createContext();

        request.setUri("/authorize");
        final FixedResponseHandler upstreamHandler = new FixedResponseHandler(upstreamResponse);
        final Promise<Response, NeverThrowsException> responsePromise = filter.filter(context, request, upstreamHandler);
        final Response response = responsePromise.getOrThrow(1, TimeUnit.SECONDS);

        assertThat(response.getStatus()).isEqualTo(Status.BAD_REQUEST);
        final JsonValue json = json(response.getEntity().getJson());
        assertThat(json.get("error").asString()).isEqualTo("invalid_request");
        assertThat(json.get("error_description").asString()).isEqualTo("'client_id' is missing in the request.");
        assertThat(FetchApiClientFilter.getApiClientFromContext(context)).isNull();
    }

    @Test
    void returnsErrorResponseWhenApiClientServiceReturnsException() throws Exception {
        final Filter filter = createFilter(Handlers.INTERNAL_SERVER_ERROR);
        final AttributesContext context = BaseResponsePathFetchApiClientFilterTest.createContext();

        final FixedResponseHandler upstreamHandler = new FixedResponseHandler(createValidUpstreamResponse());
        final Promise<Response, NeverThrowsException> responsePromise = filter.filter(context, createRequest(), upstreamHandler);
        final Response response = responsePromise.getOrThrow(1, TimeUnit.SECONDS);

        assertThat(response.getStatus()).isEqualTo(Status.INTERNAL_SERVER_ERROR);
        assertThat(FetchApiClientFilter.getApiClientFromContext(context)).isNull();
    }

    @Test
    void returnsUnauthorisedResponseWhenApiClientHasBeenDeleted() throws Exception {
        final JsonValue deletedApiClient = createIdmApiClientWithJwks(clientId).put("deleted", true);
        final MockGetApiClientIdmHandler idmResponseHandler = new MockGetApiClientIdmHandler(idmBaseUri, clientId, deletedApiClient);
        final Filter filter = createFilter(idmResponseHandler);

        final AttributesContext context = BaseResponsePathFetchApiClientFilterTest.createContext();

        final FixedResponseHandler upstreamHandler = new FixedResponseHandler(createValidUpstreamResponse());
        final Promise<Response, NeverThrowsException> responsePromise = filter.filter(context, createRequest(), upstreamHandler);
        final Response response = responsePromise.getOrThrow(1, TimeUnit.SECONDS);

        assertThat(response.getStatus()).isEqualTo(Status.UNAUTHORIZED);
        assertThat(FetchApiClientFilter.getApiClientFromContext(context)).isNull();
    }
}
