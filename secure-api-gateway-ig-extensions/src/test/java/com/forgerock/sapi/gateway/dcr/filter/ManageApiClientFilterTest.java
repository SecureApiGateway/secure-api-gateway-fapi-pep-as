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

import static com.forgerock.sapi.gateway.util.ContextUtils.REGISTRATION_REQUEST_KEY;
import static org.assertj.core.api.Assertions.assertThat;
import static org.forgerock.json.JsonValue.field;
import static org.forgerock.json.JsonValue.json;
import static org.forgerock.json.JsonValue.object;
import static org.forgerock.util.promise.Promises.newExceptionPromise;
import static org.forgerock.util.promise.Promises.newResultPromise;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import java.io.IOException;
import java.net.URISyntaxException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

import org.forgerock.http.Handler;
import org.forgerock.http.protocol.Entity;
import org.forgerock.http.protocol.Request;
import org.forgerock.http.protocol.Response;
import org.forgerock.http.protocol.Status;
import org.forgerock.json.JsonValue;
import org.forgerock.openig.fapi.apiclient.ApiClient;
import org.forgerock.openig.fapi.apiclient.ApiClientOrganisation;
import org.forgerock.openig.fapi.apiclient.service.ApiClientOrganisationService;
import org.forgerock.openig.fapi.apiclient.service.ApiClientService;
import org.forgerock.openig.fapi.apiclient.service.ApiClientServiceException;
import org.forgerock.openig.fapi.apiclient.service.ApiClientServiceException.ErrorCode;
import org.forgerock.openig.fapi.dcr.RegistrationRequest;
import org.forgerock.openig.fapi.dcr.SoftwareStatement;
import org.forgerock.openig.handler.Handlers;
import org.forgerock.openig.heap.HeapImpl;
import org.forgerock.openig.heap.Name;
import org.forgerock.services.context.AttributesContext;
import org.forgerock.services.context.Context;
import org.forgerock.services.context.RootContext;
import org.forgerock.util.promise.NeverThrowsException;
import org.forgerock.util.promise.Promise;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import com.forgerock.sapi.gateway.dcr.filter.ManageApiClientFilter.ClientIdRequestParameterLocator;
import com.forgerock.sapi.gateway.dcr.filter.ManageApiClientFilter.Heaplet;
import com.forgerock.sapi.gateway.dcr.filter.ManageApiClientFilter.PathParamClientIdRequestParameterLocator;
import com.forgerock.sapi.gateway.dcr.filter.ManageApiClientFilter.QueryParamClientIdRequestParameterLocator;
import com.forgerock.sapi.gateway.util.JsonUtils;
import com.forgerock.sapi.gateway.util.TestHandlers.FixedResponseHandler;
import com.forgerock.sapi.gateway.util.TestHandlers.TestSuccessResponseHandler;

@ExtendWith(MockitoExtension.class)
class ManageApiClientFilterTest {

    private static final String CLIENT_ID = "client-999";
    private static final ApiClientOrganisation API_CLIENT_ORGANISATION = new ApiClientOrganisation("org-1234", "Acme Fintech");

    /**
     * Successful response from the protected upstream AS's /register endpoint.
     * <p>
     * Contains a minimal OAuth2.0 /register response json payload which includes the client_id field.
     */
    private static final Response UPSTREAM_REGISTER_RESPONSE = new Response(Status.CREATED).setEntity(json(object(field("client_id", CLIENT_ID))));

    @Mock
    private ApiClientService apiClientService;
    @Mock
    private ApiClientOrganisationService apiClientOrganisationService;
    @Mock
    private SoftwareStatement softwareStatement;
    @Mock
    private RegistrationRequest registrationRequest;
    @Mock
    private ClientIdRequestParameterLocator clientIdRequestParameterLocator;
    @InjectMocks
    private ManageApiClientFilter filter;

    private Response invokeFilter(Context context, Request request, Handler responseHandler) {
        final Promise<Response, NeverThrowsException> responsePromise = filter.filter(context, request, responseHandler);
        try {
            return responsePromise.getOrThrow(1, TimeUnit.MILLISECONDS);
        } catch (InterruptedException | TimeoutException e) {
            throw new RuntimeException("Unexpected exception throw when invoking filter", e);
        }
    }

    static Context createContext() {
        return new AttributesContext(new RootContext());
    }

    private static FixedResponseHandler successfulUpstreamResponseHandler() {
        return new FixedResponseHandler(UPSTREAM_REGISTER_RESPONSE);
    }

    private void mockClientIdLocatorSuccessResponse() {
        when(clientIdRequestParameterLocator.locateClientId(any(), any())).thenReturn(CLIENT_ID);
    }

    private void mockClientIdLocatorErrorResponse() {
        when(clientIdRequestParameterLocator.locateClientId(any(), any())).thenReturn(null);
    }

    static void verifyContextContainsApiClient(Context context, ApiClient expectedApiClient) {
        assertThat(FetchApiClientFilter.getApiClientFromContext(context)).isSameAs(expectedApiClient);
    }

    static void verifyContextDoesNotContainApiClient(Context context) {
        assertThrows(IllegalStateException.class, () -> FetchApiClientFilter.getApiClientFromContext(context));
    }

    void addRegistrationRequestToAttributesContext(Context context) {
        when(registrationRequest.getSoftwareStatement()).thenReturn(softwareStatement);
        context.asContext(AttributesContext.class)
                .getAttributes()
                .put(REGISTRATION_REQUEST_KEY, registrationRequest);
    }

    private static void validateInternalServerError(Response response, String expectedErrorMessage) {
        assertThat(response.getStatus()).isEqualTo(Status.INTERNAL_SERVER_ERROR);
        validateErrorResponseEntity(response.getEntity(), expectedErrorMessage);
    }

    private static void validateUnauthorizedError(Response response, String expectedErrorMessage) {
        assertThat(response.getStatus()).isEqualTo(Status.UNAUTHORIZED);
        validateErrorResponseEntity(response.getEntity(), expectedErrorMessage);
    }

    private static void validateErrorResponseEntity(Entity entity, String expectedErrorMessage) {
        try {
            JsonUtils.assertJsonEquals(json(object(field("error", expectedErrorMessage))), json(entity.getJson()));
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    @Test
    void upstreamErrorsArePassedOn() {
        // Upstream returns FORBIDDEN error
        final Response response = invokeFilter(createContext(), new Request(), Handlers.FORBIDDEN);

        // Verify that the upstream error is passed on and that no work was done by this filter
        assertThat(response.getStatus()).isEqualTo(Status.FORBIDDEN);
        verifyNoInteractions(apiClientService, apiClientOrganisationService, softwareStatement,
                registrationRequest, clientIdRequestParameterLocator);
    }

    @Test
    void unsupportedMethodReturnsMethodNotAllowedResponse() {
        final Request request = new Request().setMethod("PATCH");
        final Response response = invokeFilter(createContext(), request, new TestSuccessResponseHandler());

        assertThat(response.getStatus()).isEqualTo(Status.METHOD_NOT_ALLOWED);
        verifyNoInteractions(apiClientService, apiClientOrganisationService, softwareStatement,
                registrationRequest, clientIdRequestParameterLocator);
    }

    @Nested
    class GetApiClient {

        Request createGetRequest() {
            try {
                return new Request().setMethod("GET").setUri("https://am/register?client_id=" + CLIENT_ID);
            } catch (URISyntaxException e) {
                throw new RuntimeException(e);
            }
        }

        @Test
        void getsApiClientWhenRegistrationIsRetrieved() {
            final ApiClient apiClient = mock(ApiClient.class);
            mockClientIdLocatorSuccessResponse();
            when(apiClientService.get(any(), eq(CLIENT_ID))).thenReturn(newResultPromise(apiClient));

            final Context context = createContext();
            final FixedResponseHandler responseHandler = successfulUpstreamResponseHandler();
            final Response response = invokeFilter(context, createGetRequest(), responseHandler);

            assertThat(response).isEqualTo(UPSTREAM_REGISTER_RESPONSE);
            verifyContextContainsApiClient(context, apiClient);
            verify(apiClientService, times(1)).get(any(), eq(CLIENT_ID));
            verifyNoInteractions(apiClientOrganisationService);
        }

        @Test
        void failsWhenUnableToLocateClientId() {
            mockClientIdLocatorErrorResponse();

            final Context context = createContext();
            final FixedResponseHandler responseHandler = successfulUpstreamResponseHandler();
            final Response response = invokeFilter(context, createGetRequest(), responseHandler);

            validateInternalServerError(response, "client_id not found");
            verifyContextDoesNotContainApiClient(context);
            verifyNoInteractions(apiClientService, apiClientOrganisationService);
        }

        /**
         * ClientIdRequestParameterLocator contract is to return null rather than throw an exception.
         *
         * Test that any custom impls which do not adhere to this contract do not cause RuntimeExceptions to be
         * thrown by the filter.
         */
        @Test
        void failsWhenClientIdRequestParameterLocatorThrowsUnexpectedException() {
            when(clientIdRequestParameterLocator.locateClientId(any(), any())).thenThrow(new NullPointerException("oops"));

            final Context context = createContext();
            final FixedResponseHandler responseHandler = successfulUpstreamResponseHandler();
            final Response response = invokeFilter(context, createGetRequest(), responseHandler);

            validateInternalServerError(response, "client_id not found");
            verifyContextDoesNotContainApiClient(context);
            verifyNoInteractions(apiClientService, apiClientOrganisationService);
        }

        @Test
        void returnsErrorDueToApiClientServiceError() {
            mockClientIdLocatorSuccessResponse();
            when(apiClientService.get(any(), eq(CLIENT_ID)))
                    .thenReturn(newExceptionPromise(
                            new ApiClientServiceException(ErrorCode.SERVER_ERROR, "Unable to connect to IDM")));

            final Context context = createContext();
            final FixedResponseHandler responseHandler = successfulUpstreamResponseHandler();
            final Response response = invokeFilter(context, createGetRequest(), responseHandler);
            validateInternalServerError(response, "Failed to get ApiClient");
            verifyContextDoesNotContainApiClient(context);
        }

        @Test
        void returnsUnauthorisedWhenApiClientHasBeenDeleted() {
            mockClientIdLocatorSuccessResponse();
            when(apiClientService.get(any(), eq(CLIENT_ID)))
                    .thenReturn(newExceptionPromise(
                            new ApiClientServiceException(ErrorCode.DELETED, "ApiClient has been deleted")));

            final Context context = createContext();
            final FixedResponseHandler responseHandler = successfulUpstreamResponseHandler();
            final Response response = invokeFilter(context, createGetRequest(), responseHandler);
            validateUnauthorizedError(response, "Failed to get ApiClient");
            verifyContextDoesNotContainApiClient(context);
        }
    }

    @Nested
    class CreateApiClient {

        private static Request createPostRequest() {
            try {
                return new Request().setMethod("POST").setUri("https://am/register");
            } catch (URISyntaxException e) {
                throw new RuntimeException(e);
            }
        }

        @Test
        void createsApiClientWhenRegistrationIsSuccessful() {
            final ApiClient apiClient = mock(ApiClient.class);
            when(apiClientService.create(any(), eq(CLIENT_ID), eq(softwareStatement))).thenReturn(newResultPromise(apiClient));
            when(apiClientOrganisationService.create(any(), eq(softwareStatement))).thenReturn(newResultPromise(API_CLIENT_ORGANISATION));

            final Context context = createContext();
            addRegistrationRequestToAttributesContext(context);

            final FixedResponseHandler responseHandler = successfulUpstreamResponseHandler();
            final Response response = invokeFilter(context, createPostRequest(), responseHandler);

            assertThat(response).isEqualTo(UPSTREAM_REGISTER_RESPONSE);
            verifyContextContainsApiClient(context, apiClient);
            verify(apiClientService, times(1)).create(any(), eq(CLIENT_ID), eq(softwareStatement));
            verify(apiClientOrganisationService, times(1)).create(any(), eq(softwareStatement));
        }

        @Test
        void returnsErrorWhenRegistrationRequestNotInAttributesContext() {
            final Context context = createContext();
            final FixedResponseHandler responseHandler = successfulUpstreamResponseHandler();
            final IllegalStateException illegalStateException = assertThrows(IllegalStateException.class,
                    () -> invokeFilter(context, createPostRequest(), responseHandler));


            assertThat(illegalStateException).hasMessageContaining("Required attribute: \"registrationRequest\" not found in context");

            verifyNoInteractions(apiClientService, apiClientOrganisationService);
        }

        @Test
        void returnsErrorDueToMalformedRegisterResponse() {
            final Context context = createContext();
            addRegistrationRequestToAttributesContext(context);

            final Response malformedUpstreamResponse = new Response(Status.OK).setEntity("invalid OAuth2.0 /register response entity");
            final FixedResponseHandler responseHandler = new FixedResponseHandler(malformedUpstreamResponse);
            final Response response = invokeFilter(context, createPostRequest(), responseHandler);

            validateInternalServerError(response, "client_id field not found in registration response");
            verifyContextDoesNotContainApiClient(context);
            verifyNoInteractions(apiClientService, apiClientOrganisationService);
        }

        @Test
        void returnsErrorWhenRegistrationResponseIsMissingClientId() {
            final Context context = createContext();
            addRegistrationRequestToAttributesContext(context);

            final Response malformedUpstreamResponse = new Response(Status.OK).setEntity(json(object(field("field1", "value1"))));
            final FixedResponseHandler responseHandler = new FixedResponseHandler(malformedUpstreamResponse);
            final Response response = invokeFilter(context, createPostRequest(), responseHandler);

            validateInternalServerError(response, "client_id field not found in registration response");
            verifyContextDoesNotContainApiClient(context);
            verifyNoInteractions(apiClientService, apiClientOrganisationService);
        }

        @Test
        void returnsErrorDueToApiClientOrganisationServiceError() {
            // Simulate error creating ApiClientOrganisation
            when(apiClientOrganisationService.create(any(), eq(softwareStatement)))
                    .thenReturn(newExceptionPromise(new ApiClientServiceException(ErrorCode.SERVER_ERROR, "Connection Refused")));

            final Context context = createContext();
            addRegistrationRequestToAttributesContext(context);

            final FixedResponseHandler responseHandler = successfulUpstreamResponseHandler();
            final Response response = invokeFilter(context, createPostRequest(), responseHandler);

            validateInternalServerError(response, "Failed to create ApiClientOrganisation");
            verifyContextDoesNotContainApiClient(context);
            verifyNoInteractions(apiClientService);
        }

        @Test
        void returnsErrorDueToApiClientServiceError() {
            when(apiClientOrganisationService.create(any(), eq(softwareStatement))).thenReturn(newResultPromise(API_CLIENT_ORGANISATION));
            when(apiClientService.create(any(), eq(CLIENT_ID), eq(softwareStatement)))
                    .thenReturn(newExceptionPromise(new ApiClientServiceException(ErrorCode.SERVER_ERROR, "Connection refused")));

            final Context context = createContext();
            addRegistrationRequestToAttributesContext(context);

            final FixedResponseHandler responseHandler = successfulUpstreamResponseHandler();
            final Response response = invokeFilter(context, createPostRequest(), responseHandler);
            validateInternalServerError(response, "Failed to create ApiClient");
        }
    }

    @Nested
    class UpdateApiClient {

        private Request createPutRequest() {
            try {
                return new Request().setMethod("PUT").setUri("https://am/register?client_id="+CLIENT_ID);
            } catch (URISyntaxException e) {
                throw new RuntimeException(e);
            }
        }

        @Test
        void updatesApiClientWhenRegistrationUpdateIsSuccessful()  {
            final ApiClient apiClient = mock(ApiClient.class);
            when(apiClientService.update(any(), eq(CLIENT_ID), eq(softwareStatement))).thenReturn(newResultPromise(apiClient));

            final Context context = createContext();
            addRegistrationRequestToAttributesContext(context);

            final Response response = invokeFilter(context, createPutRequest(), successfulUpstreamResponseHandler());

            assertThat(response).isEqualTo(UPSTREAM_REGISTER_RESPONSE);
            verifyContextContainsApiClient(context, apiClient);
            verify(apiClientService, times(1)).update(any(), eq(CLIENT_ID), eq(softwareStatement));
            verifyNoInteractions(apiClientOrganisationService);
        }

        @Test
        void returnsErrorWhenRegistrationRequestNotInAttributesContext() {
            final Context context = createContext();
            final FixedResponseHandler responseHandler = successfulUpstreamResponseHandler();
            final IllegalStateException illegalStateException = assertThrows(IllegalStateException.class,
                    () -> invokeFilter(context, createPutRequest(), responseHandler));


            assertThat(illegalStateException).hasMessageContaining(
                    "Required attribute: \"registrationRequest\" not found in context");

            verifyNoInteractions(apiClientService, apiClientOrganisationService);
        }

        @Test
        void returnsErrorDueToMalformedRegisterResponse() {
            final Context context = createContext();
            addRegistrationRequestToAttributesContext(context);

            final Response malformedUpstreamResponse = new Response(Status.OK).setEntity("invalid OAuth2.0 /register response entity");
            final FixedResponseHandler responseHandler = new FixedResponseHandler(malformedUpstreamResponse);
            final Response response = invokeFilter(context, createPutRequest(), responseHandler);

            validateInternalServerError(response, "client_id field not found in registration response");
            verifyContextDoesNotContainApiClient(context);
            verifyNoInteractions(apiClientService, apiClientOrganisationService);
        }
    }

    @Nested
    class DeleteApiClient {

        private static Request createDeleteRequest() {
            try {
                return new Request().setMethod("DELETE").setUri("https://am/register?client_id=" + CLIENT_ID);
            } catch (URISyntaxException e) {
                throw new RuntimeException(e);
            }
        }

        @Test
        void deletesApiClientWhenRegistrationIsDeleted() {
            final ApiClient apiClient = mock(ApiClient.class);
            mockClientIdLocatorSuccessResponse();
            when(apiClientService.delete(any(), eq(CLIENT_ID))).thenReturn(newResultPromise(apiClient));

            final Context context = createContext();
            final Request request = createDeleteRequest();
            final FixedResponseHandler responseHandler = successfulUpstreamResponseHandler();
            final Response response = invokeFilter(context, request, responseHandler);

            // The upstream response is not returned for a delete, instead a new 204 No Content response is returned
            // This is because upstream servers may return 200 (AM does this).
            assertThat(response.getStatus()).isEqualTo(Status.NO_CONTENT);
            verifyContextContainsApiClient(context, apiClient);
            verify(apiClientService, times(1)).delete(any(), eq(CLIENT_ID));
            verifyNoInteractions(apiClientOrganisationService);
        }

        @Test
        void failsWhenUnableToLocateClientId() {
            mockClientIdLocatorErrorResponse();

            final Context context = createContext();
            final Request request = createDeleteRequest();
            final FixedResponseHandler responseHandler = successfulUpstreamResponseHandler();
            final Response response = invokeFilter(context, request, responseHandler);

            validateInternalServerError(response, "client_id not found");

            verifyContextDoesNotContainApiClient(context);
            verifyNoInteractions(apiClientService, apiClientOrganisationService);
        }

        /**
         * ClientIdRequestParameterLocator contract is to return null rather than throw an exception.
         *
         * Test that any custom impls which do not adhere to this contract do not cause RuntimeExceptions to be
         * thrown by the filter.
         */
        @Test
        void failsWhenClientIdRequestParameterLocatorThrowsUnexpectedException() {
            when(clientIdRequestParameterLocator.locateClientId(any(), any())).thenThrow(new NullPointerException("oops"));

            final Context context = createContext();
            final FixedResponseHandler responseHandler = successfulUpstreamResponseHandler();
            final Response response = invokeFilter(context, createDeleteRequest(), responseHandler);

            validateInternalServerError(response, "client_id not found");
            verifyContextDoesNotContainApiClient(context);
            verifyNoInteractions(apiClientService, apiClientOrganisationService);
        }

        @Test
        void returnsErrorDueToApiClientServiceError() {
            mockClientIdLocatorSuccessResponse();
            when(apiClientService.delete(any(), eq(CLIENT_ID)))
                    .thenReturn(newExceptionPromise(
                            new ApiClientServiceException(ErrorCode.SERVER_ERROR, "Unable to connect to IDM")));

            final Context context = createContext();
            final FixedResponseHandler responseHandler = successfulUpstreamResponseHandler();
            final Response response = invokeFilter(context, createDeleteRequest(), responseHandler);
            validateInternalServerError(response, "Failed to delete ApiClient");
            verifyContextDoesNotContainApiClient(context);
        }

    }

    @Nested
    class HeapletTest {
        @Test
        void createsFilter() throws Exception {
            final HeapImpl heap = new HeapImpl(Name.of("heap"));
            heap.put("mockApiClientService", apiClientService);
            heap.put("mockApiClientOrgService", apiClientOrganisationService);
            heap.put("mockClientIdRequestParameterLocator", clientIdRequestParameterLocator);

            final JsonValue config = json(object(field("apiClientService", "mockApiClientService"),
                                                 field("apiClientOrgService", "mockApiClientOrgService"),
                                                 field("clientIdRequestParameterLocator", "mockClientIdRequestParameterLocator")));

            final ManageApiClientFilter filter = (ManageApiClientFilter) new Heaplet().create(Name.of("test"), config, heap);
            assertNotNull(filter);
        }
    }

    @Nested
    class ClientIdRequestParameterLocatorTest {

        @Test
        public void locatesClientIdInQueryParam() throws Exception {
            final QueryParamClientIdRequestParameterLocator clientIdLocator = new QueryParamClientIdRequestParameterLocator();
            final Request request = new Request().setUri("https://am/register?client_id=client-1234");
            assertThat(clientIdLocator.locateClientId(new RootContext(), request)).isEqualTo("client-1234");
        }

        @Test
        public void locatesClientIdPathParam() throws Exception {
            final PathParamClientIdRequestParameterLocator clientIdLocator = new PathParamClientIdRequestParameterLocator();
            final Request request = new Request().setUri("https://am/register/9993-3332-ssss-dddd");
            assertThat(clientIdLocator.locateClientId(new RootContext(), request)).isEqualTo("9993-3332-ssss-dddd");
        }

        @Test
        public void returnsNullWhenUnableToLocateClientId() throws Exception {
            assertThat(new PathParamClientIdRequestParameterLocator().locateClientId(new RootContext(), new Request().setUri("https://am"))).isNull();
            assertThat(new QueryParamClientIdRequestParameterLocator().locateClientId(new RootContext(), new Request().setUri("https://am"))).isNull();
        }
    }

}