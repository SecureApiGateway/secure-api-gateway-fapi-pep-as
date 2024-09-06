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

import static org.assertj.core.api.Assertions.assertThat;
import static org.forgerock.json.JsonValue.json;
import static org.forgerock.util.promise.Promises.newExceptionPromise;
import static org.forgerock.util.promise.Promises.newResultPromise;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.when;

import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.function.Consumer;

import org.forgerock.http.Filter;
import org.forgerock.http.protocol.Request;
import org.forgerock.http.protocol.Response;
import org.forgerock.http.protocol.Status;
import org.forgerock.json.JsonValue;
import org.forgerock.services.context.AttributesContext;
import org.forgerock.services.context.RootContext;
import org.forgerock.util.promise.NeverThrowsException;
import org.forgerock.util.promise.Promise;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import com.forgerock.sapi.gateway.dcr.models.ApiClient;
import com.forgerock.sapi.gateway.dcr.service.ApiClientService;
import com.forgerock.sapi.gateway.dcr.service.ApiClientServiceException;
import com.forgerock.sapi.gateway.dcr.service.ApiClientServiceException.ErrorCode;
import com.forgerock.sapi.gateway.util.TestHandlers.FixedResponseHandler;

@ExtendWith(MockitoExtension.class)
public abstract class BaseResponsePathFetchApiClientFilterTest {

    @Mock
    protected ApiClient testApiClient;

    @Mock
    protected ApiClientService apiClientService;

    protected static final String CLIENT_ID = "9999";

    private static AttributesContext createContext() {
        return new AttributesContext(new RootContext("root"));
    }

    protected abstract Filter createFilter();

    @Test
    void fetchApiClientForSuccessResponse() throws Exception {
        callFilterValidateSuccessBehaviour(createFilter());
    }

    protected void callFilterValidateSuccessBehaviour(Filter filter) throws Exception {
        // Mock the success response for the ApiClientService call
        when(apiClientService.getApiClient(eq(CLIENT_ID))).thenReturn(newResultPromise(testApiClient));

        final Consumer<AttributesContext> successBehaviourValidator = ctxt -> {
            // Verify that the context was updated with the apiClient data
            final ApiClient apiClient = FetchApiClientFilter.getApiClientFromContext(ctxt);
            assertNotNull(apiClient, "apiClient was not found in context");
            assertThat(apiClient).isSameAs(testApiClient);
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
        final AttributesContext context = BaseResponsePathFetchApiClientFilterTest.createContext();

        final Promise<Response, NeverThrowsException> responsePromise = createFilter().filter(context, createRequest(),
                                                                                              new FixedResponseHandler(new Response(Status.BAD_GATEWAY)));

        final Response response = responsePromise.getOrThrow(1, TimeUnit.SECONDS);

        assertThat(response.getStatus()).isEqualTo(Status.BAD_GATEWAY);
        verifyApiClientNotInContext(context);
    }

    void returnsErrorResponseWhenClientIdParamNotFound(Request request, Response upstreamResponse) throws Exception {
        final AttributesContext context = BaseResponsePathFetchApiClientFilterTest.createContext();

        request.setUri("/authorize");
        final FixedResponseHandler upstreamHandler = new FixedResponseHandler(upstreamResponse);
        final Promise<Response, NeverThrowsException> responsePromise = createFilter().filter(context, request, upstreamHandler);
        final Response response = responsePromise.getOrThrow(1, TimeUnit.SECONDS);

        assertThat(response.getStatus()).isEqualTo(Status.BAD_REQUEST);
        final JsonValue json = json(response.getEntity().getJson());
        assertThat(json.get("error").asString()).isEqualTo("invalid_request");
        assertThat(json.get("error_description").asString()).isEqualTo("'client_id' is missing in the request.");
        verifyApiClientNotInContext(context);
    }

    @Test
    void returnsErrorResponseWhenApiClientServiceReturnsException() throws Exception {
        when(apiClientService.getApiClient(eq(CLIENT_ID))).thenReturn(
                newExceptionPromise(new ApiClientServiceException(ApiClientServiceException.ErrorCode.SERVER_ERROR, "Unexpected error")));

        final AttributesContext context = BaseResponsePathFetchApiClientFilterTest.createContext();

        final FixedResponseHandler upstreamHandler = new FixedResponseHandler(createValidUpstreamResponse());
        final Promise<Response, NeverThrowsException> responsePromise = createFilter().filter(context, createRequest(), upstreamHandler);
        final Response response = responsePromise.getOrThrow(1, TimeUnit.SECONDS);

        assertThat(response.getStatus()).isEqualTo(Status.INTERNAL_SERVER_ERROR);
        verifyApiClientNotInContext(context);
    }

    private static void verifyApiClientNotInContext(AttributesContext context) {
        assertThrows(IllegalStateException.class, () -> FetchApiClientFilter.getApiClientFromContext(context));
    }

    @ParameterizedTest
    @EnumSource(value = ErrorCode.class, names = {"NOT_FOUND", "DELETED"})
    void returnsUnauthorisedResponseWhenApiClientHasBeenDeleted(ErrorCode errorCode) throws Exception {
        // Mock error response from ApiClientService
        when(apiClientService.getApiClient(eq(CLIENT_ID))).thenReturn(
                newExceptionPromise(new ApiClientServiceException(errorCode,
                                                                  "ApiClient " + CLIENT_ID + " does not exist")));

        final AttributesContext context = createContext();
        final FixedResponseHandler upstreamHandler = new FixedResponseHandler(createValidUpstreamResponse());

        final Promise<Response, NeverThrowsException> responsePromise = createFilter().filter(context, createRequest(), upstreamHandler);
        final Response response = responsePromise.getOrThrow(1, TimeUnit.SECONDS);

        assertThat(response.getStatus()).isEqualTo(Status.UNAUTHORIZED);
        verifyApiClientNotInContext(context);
    }
}
