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
package com.forgerock.sapi.gateway.dcr.service.idm;

import static com.forgerock.sapi.gateway.dcr.service.idm.IdmApiClientDecoderTest.createIdmApiClientWithJwks;
import static com.forgerock.sapi.gateway.dcr.service.idm.IdmApiClientDecoderTest.verifyIdmClientDataMatchesApiClientObject;
import static com.forgerock.sapi.gateway.util.JsonUtils.assertJsonEquals;
import static org.forgerock.json.JsonValue.array;
import static org.forgerock.json.JsonValue.field;
import static org.forgerock.json.JsonValue.json;
import static org.forgerock.json.JsonValue.object;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import java.util.stream.Stream;

import org.forgerock.http.Client;
import org.forgerock.http.Handler;
import org.forgerock.http.MutableUri;
import org.forgerock.http.header.ContentTypeHeader;
import org.forgerock.http.protocol.Entity;
import org.forgerock.http.protocol.Form;
import org.forgerock.http.protocol.Request;
import org.forgerock.http.protocol.Response;
import org.forgerock.http.protocol.Status;
import org.forgerock.json.JsonValue;
import org.forgerock.json.JsonValueException;
import org.forgerock.json.jose.jwk.JWKSet;
import org.forgerock.openig.handler.Handlers;
import org.forgerock.util.promise.Promise;
import org.forgerock.util.promise.Promises;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;

import com.forgerock.sapi.gateway.dcr.models.ApiClient;
import com.forgerock.sapi.gateway.dcr.models.SoftwareStatement;
import com.forgerock.sapi.gateway.dcr.service.ApiClientService;
import com.forgerock.sapi.gateway.dcr.service.ApiClientServiceException;
import com.forgerock.sapi.gateway.dcr.service.ApiClientServiceException.ErrorCode;

public class IdmApiClientServiceTest {

    private static final String TEST_IDM_BASE_URI = "http://localhost/openidm/managed";
    private static final String TEST_CLIENT_ID = "9999";
    private static final IdmApiClientDecoder IDM_API_CLIENT_DECODER = new IdmApiClientDecoder();

    @Test
    void testGetApiClient() throws Exception {
        final JsonValue idmClientData = createIdmApiClientWithJwks(TEST_CLIENT_ID);
        final MockGetApiClientIdmHandler idmResponseHandler = new MockGetApiClientIdmHandler(TEST_IDM_BASE_URI, TEST_CLIENT_ID, idmClientData);

        final ApiClientService apiClientService = new IdmApiClientService(new Client(idmResponseHandler), TEST_IDM_BASE_URI, IDM_API_CLIENT_DECODER);
        final Promise<ApiClient, ApiClientServiceException> apiClientPromise = apiClientService.getApiClient(TEST_CLIENT_ID);
        final ApiClient apiClient = apiClientPromise.get(1, TimeUnit.MILLISECONDS);

        verifyIdmClientDataMatchesApiClientObject(idmClientData, apiClient);
    }

    @Test
    void testThrowsExceptionIfIdmReturnsNotFound() {
        final Handler notFoundResponseHandler = (ctxt, req) -> Promises.newResultPromise(new Response(Status.NOT_FOUND));
        final ApiClientService apiClientService = new IdmApiClientService(new Client(notFoundResponseHandler), TEST_IDM_BASE_URI, IDM_API_CLIENT_DECODER);

        final Promise<ApiClient, ApiClientServiceException> apiClientPromise = apiClientService.getApiClient(TEST_CLIENT_ID);
        final ApiClientServiceException exception = assertThrows(ApiClientServiceException.class, () -> apiClientPromise.getOrThrow(1, TimeUnit.MILLISECONDS));

        assertEquals(ErrorCode.NOT_FOUND, exception.getErrorCode());
        assertEquals("[NOT_FOUND] ApiClient not found for apiClientId: 9999", exception.getMessage());
    }

    @Test
    void testThrowsExceptionIfApiClientHasBeenDeleted() {
        final JsonValue idmClientData = createIdmApiClientWithJwks(TEST_CLIENT_ID);
        idmClientData.put("deleted", Boolean.TRUE);
        final MockGetApiClientIdmHandler idmResponseHandler = new MockGetApiClientIdmHandler(TEST_IDM_BASE_URI, TEST_CLIENT_ID, idmClientData);

        final ApiClientService apiClientService = new IdmApiClientService(new Client(idmResponseHandler), TEST_IDM_BASE_URI, IDM_API_CLIENT_DECODER);
        final Promise<ApiClient, ApiClientServiceException> apiClientPromise = apiClientService.getApiClient(TEST_CLIENT_ID);
        final ApiClientServiceException exception = assertThrows(ApiClientServiceException.class, () -> apiClientPromise.getOrThrow(1, TimeUnit.MILLISECONDS));
        assertEquals("[DELETED] ApiClient apiClientId: 9999 has been deleted", exception.getMessage());
        assertEquals(ErrorCode.DELETED, exception.getErrorCode());
    }

    @Test
    void testThrowsExceptionWhenIdmReturnsErrorResponseForGetRequest() {
        final Handler idmResponse = Handlers.INTERNAL_SERVER_ERROR;
        final ApiClientService apiClientService = new IdmApiClientService(new Client(idmResponse), TEST_IDM_BASE_URI, IDM_API_CLIENT_DECODER);
        final Promise<ApiClient, ApiClientServiceException> apiClientPromise = apiClientService.getApiClient(TEST_CLIENT_ID);
        final ApiClientServiceException exception = assertThrows(ApiClientServiceException.class, () -> apiClientPromise.getOrThrow(1, TimeUnit.MILLISECONDS));

        assertEquals("[SERVER_ERROR] Failed to get ApiClient from IDM, response status: [Status: 500 Internal Server Error]",
                exception.getMessage());
        assertEquals(ErrorCode.SERVER_ERROR, exception.getErrorCode());
    }

    @Test
    void testThrowsExceptionWhenIdmReturnsNonJsonResponse() {
        // IDM returns a Form instead of json
        final Client idmClientHandler;
        try (Response invalidIdmResponse = new Response(Status.OK).setEntity(new Form())) {
            idmClientHandler = new Client((ctx, req) -> Promises.newResultPromise(invalidIdmResponse));
        }

        final ApiClientService apiClientService = new IdmApiClientService(idmClientHandler, TEST_IDM_BASE_URI, IDM_API_CLIENT_DECODER);
        final Promise<ApiClient, ApiClientServiceException> apiClient = apiClientService.getApiClient("123");
        final ApiClientServiceException exception = assertThrows(ApiClientServiceException.class, () -> apiClient.getOrThrow(1, TimeUnit.MILLISECONDS));

        assertEquals("[SERVER_ERROR] Failed to get response json entity", exception.getMessage());
        assertEquals(ErrorCode.SERVER_ERROR, exception.getErrorCode());
    }

    @Test
    void testThrowsExceptionWhenIdmReturnsApiClientMissingRequiredFields() {
        final JsonValue idmClientData = createIdmApiClientWithJwks(TEST_CLIENT_ID);
        idmClientData.remove("ssa"); // Remove the required ssa field
        final MockGetApiClientIdmHandler idmResponseHandler = new MockGetApiClientIdmHandler(TEST_IDM_BASE_URI, TEST_CLIENT_ID, idmClientData);

        final ApiClientService apiClientService = new IdmApiClientService(new Client(idmResponseHandler), TEST_IDM_BASE_URI, IDM_API_CLIENT_DECODER);
        final Promise<ApiClient, ApiClientServiceException> apiClientPromise = apiClientService.getApiClient(TEST_CLIENT_ID);
        final ApiClientServiceException exception = assertThrows(ApiClientServiceException.class, () -> apiClientPromise.getOrThrow(1, TimeUnit.MILLISECONDS));

        assertEquals("[DECODE_FAILED] Failed to decode apiClient response json", exception.getMessage());
        assertEquals(ErrorCode.DECODE_FAILED, exception.getErrorCode());
        assertEquals(JsonValueException.class, exception.getCause().getClass());
        assertEquals("/ssa: is a required field, failed to decode IDM ApiClient", exception.getCause().getMessage());
    }

    @Test
    void failsToConstructServiceWithBadIdmUri() {
        final String badIdmUri = "999://localhost/openidm/managed/";

        final IllegalStateException illegalStateException = assertThrows(IllegalStateException.class,
                () -> new IdmApiClientService(new Client(Handlers.FORBIDDEN), badIdmUri, IDM_API_CLIENT_DECODER));

        assertEquals("Failed to create URI", illegalStateException.getMessage());
        assertInstanceOf(URISyntaxException.class, illegalStateException.getCause());
    }

    @ParameterizedTest
    @ValueSource(strings = {TEST_IDM_BASE_URI, TEST_IDM_BASE_URI + "/"})
    void shouldRemoveTrailingSlashInIdmBaseUri(String baseUri) throws URISyntaxException {
        final IdmApiClientService idmApiClientService = new IdmApiClientService(new Client(Handlers.FORBIDDEN), baseUri, IDM_API_CLIENT_DECODER);

        assertEquals("http://localhost/openidm/managed/apiClient/client-1234",
                idmApiClientService.createIdmUri("client-1234", Map.of()).toString());
    }

    @ParameterizedTest
    @MethodSource("shouldBuildIdmUrisArguments")
    void shouldBuildIdmUris(String expectedUri, String clientId, Map<String, String> queryParams) throws URISyntaxException {
        final IdmApiClientService idmApiClientService = new IdmApiClientService(new Client(Handlers.FORBIDDEN), TEST_IDM_BASE_URI, IDM_API_CLIENT_DECODER);
        assertEquals(expectedUri, idmApiClientService.createIdmUri(clientId, queryParams).toString());
    }

    static Stream<Arguments> shouldBuildIdmUrisArguments() {
        return Stream.of(
                Arguments.of("http://localhost/openidm/managed/apiClient", null, null),
                Arguments.of("http://localhost/openidm/managed/apiClient/client-999", "client-999", null),
                Arguments.of("http://localhost/openidm/managed/apiClient?param1=xyz&param2=999", null, new LinkedHashMap<>() {{
                    put("param1", "xyz");
                    put("param2", "999");
                }}),
                Arguments.of("http://localhost/openidm/managed/apiClient/client-1234?_fields=apiClientOrg/*,*", "client-1234", Map.of("_fields", "apiClientOrg/*,*"))
        );
    }

    @Test
    void testCreateApiClient() throws Exception {
        // ApiClient data that IDM will return
        final JsonValue createApiClientResponseData = createIdmApiClientWithJwks(TEST_CLIENT_ID);

        final JsonValue expectedCreateApiClientRequestJson = buildExpectedCreateOrUpdateRequestJson(createApiClientResponseData);

        final MockCreateApiClientIdmHandler idmResponseHandler = new MockCreateApiClientIdmHandler(
                TEST_IDM_BASE_URI, expectedCreateApiClientRequestJson, createApiClientResponseData);

        final ApiClientService apiClientService = new IdmApiClientService(
                new Client(idmResponseHandler), TEST_IDM_BASE_URI, IDM_API_CLIENT_DECODER);

        final SoftwareStatement softwareStatement = mockSoftwareStatement(createApiClientResponseData);

        final Promise<ApiClient, ApiClientServiceException> apiClientPromise = apiClientService.createApiClient(TEST_CLIENT_ID, softwareStatement);
        final ApiClient apiClient = apiClientPromise.get(1, TimeUnit.MILLISECONDS);

        verifyIdmClientDataMatchesApiClientObject(createApiClientResponseData, apiClient);
    }

    // Json payload that we expected IDM to recv for a Create or Update operation
    private static JsonValue buildExpectedCreateOrUpdateRequestJson(JsonValue idmResponseData) {
        final JsonValue expectedCreateApiClientRequestJson = idmResponseData.copy();
        // In the request, the apiClientOrg is just a relationship mapping and does not contain the id and name fields
        expectedCreateApiClientRequestJson.put("apiClientOrg", object(
                field("_ref", "managed/apiClientOrg/" + idmResponseData.get("apiClientOrg").get("id").asString())));
        return expectedCreateApiClientRequestJson;
    }

    private SoftwareStatement mockSoftwareStatement(JsonValue createApiClientJson) {
        final SoftwareStatement softwareStatement = mock(SoftwareStatement.class);
        when(softwareStatement.getSoftwareId()).thenReturn(createApiClientJson.get("id").asString());
        when(softwareStatement.getClientName()).thenReturn(createApiClientJson.get("name").asString());
        when(softwareStatement.getB64EncodedJwtString()).thenReturn(createApiClientJson.get("ssa").asString());
        when(softwareStatement.getRoles()).thenReturn(createApiClientJson.get("roles").asList(String.class));

        if (createApiClientJson.get("jwksUri").isNotNull()) {
            when(softwareStatement.hasJwksUri()).thenReturn(true);
            try {
                when(softwareStatement.getJwksUri()).thenReturn(URI.create(createApiClientJson.get("jwksUri").asString()).toURL());
            } catch (MalformedURLException e) {
                throw new RuntimeException(e);
            }
        }
        else if (createApiClientJson.get("jwks").isNotNull()) {
            when(softwareStatement.hasJwksUri()).thenReturn(false);
            when(softwareStatement.getJwksSet()).thenReturn(JWKSet.parse(createApiClientJson.get("jwks")));
        }

        when(softwareStatement.getOrgId()).thenReturn(createApiClientJson.get("apiClientOrg").get("id").asString());
        return softwareStatement;
    }

    @Test
    void testThrowsExceptionWhenIdmReturnsErrorResponseForCreate() {
        final Handler idmResponse = Handlers.INTERNAL_SERVER_ERROR;
        final ApiClientService apiClientService = new IdmApiClientService(new Client(idmResponse), TEST_IDM_BASE_URI, IDM_API_CLIENT_DECODER);
        final Promise<ApiClient, ApiClientServiceException> apiClientPromise = apiClientService.createApiClient(TEST_CLIENT_ID, mockSoftwareStatement(createIdmApiClientWithJwks(TEST_CLIENT_ID)));
        final ApiClientServiceException exception = assertThrows(ApiClientServiceException.class, () -> apiClientPromise.getOrThrow(1, TimeUnit.MILLISECONDS));

        assertEquals("[SERVER_ERROR] Failed to get ApiClient from IDM, response status: [Status: 500 Internal Server Error]",
                exception.getMessage());
        assertEquals(ErrorCode.SERVER_ERROR, exception.getErrorCode());
    }

    @Test
    void testBuildApiClientRequestJsonForApiClientWithJwksUri() {
        final IdmApiClientService idmApiClientService = new IdmApiClientService(new Client(Handlers.FORBIDDEN), TEST_IDM_BASE_URI, IDM_API_CLIENT_DECODER);
        final JsonValue idmApiClientWithJwksUri = IdmApiClientDecoderTest.createIdmApiClientWithJwksUri(TEST_CLIENT_ID);

        final JsonValue requestJson = idmApiClientService.buildApiClientRequestJson(TEST_CLIENT_ID, mockSoftwareStatement(idmApiClientWithJwksUri));
        assertJsonEquals(buildExpectedCreateOrUpdateRequestJson(idmApiClientWithJwksUri), requestJson);
    }

    @Test
    void testBuildApiClientRequestJsonForApiClientWithEmbeddedJwks() {
        final IdmApiClientService idmApiClientService = new IdmApiClientService(new Client(Handlers.FORBIDDEN), TEST_IDM_BASE_URI, IDM_API_CLIENT_DECODER);
        final JsonValue idmApiClientWithEmbeddedJwks = createIdmApiClientWithJwks(TEST_CLIENT_ID);

        final JsonValue requestJson = idmApiClientService.buildApiClientRequestJson(TEST_CLIENT_ID, mockSoftwareStatement(idmApiClientWithEmbeddedJwks));
        assertJsonEquals(buildExpectedCreateOrUpdateRequestJson(idmApiClientWithEmbeddedJwks), requestJson);
    }



    @Test
    void testDeleteApiClient() throws Exception {
        // ApiClient data that IDM will return
        final JsonValue idmApiClientResponseData = createIdmApiClientWithJwks(TEST_CLIENT_ID);
        idmApiClientResponseData.put("deleted", true);

        final MockDeleteApiClientIdmHandler idmResponseHandler = new MockDeleteApiClientIdmHandler(
                TEST_IDM_BASE_URI, TEST_CLIENT_ID, idmApiClientResponseData);

        final ApiClientService apiClientService = new IdmApiClientService(
                new Client(idmResponseHandler), TEST_IDM_BASE_URI, IDM_API_CLIENT_DECODER);

        final Promise<ApiClient, ApiClientServiceException> apiClientPromise = apiClientService.deleteApiClient(TEST_CLIENT_ID);
        final ApiClient apiClient = apiClientPromise.get(1, TimeUnit.MILLISECONDS);
        verifyIdmClientDataMatchesApiClientObject(idmApiClientResponseData, apiClient, true);
    }

    @Test
    void testUpdateApiClient() throws Exception {
        // ApiClient data that IDM will return
        final JsonValue idmResponseData = createIdmApiClientWithJwks(TEST_CLIENT_ID);

        final JsonValue expectedCreateApiClientRequestJson = buildExpectedCreateOrUpdateRequestJson(idmResponseData);

        final MockUpdateApiClientIdmHandler idmResponseHandler = new MockUpdateApiClientIdmHandler(
                TEST_IDM_BASE_URI, TEST_CLIENT_ID, expectedCreateApiClientRequestJson, idmResponseData);

        final ApiClientService apiClientService = new IdmApiClientService(
                new Client(idmResponseHandler), TEST_IDM_BASE_URI, IDM_API_CLIENT_DECODER);

        final SoftwareStatement softwareStatement = mockSoftwareStatement(idmResponseData);

        final Promise<ApiClient, ApiClientServiceException> apiClientPromise = apiClientService.updateApiClient(TEST_CLIENT_ID, softwareStatement);
        final ApiClient apiClient = apiClientPromise.get(1, TimeUnit.MILLISECONDS);

        verifyIdmClientDataMatchesApiClientObject(idmResponseData, apiClient);
    }


    public static class MockGetApiClientIdmHandler extends BaseMockIdmResponseHandler {

        private final String expectedClientId;

        public MockGetApiClientIdmHandler(String idmBaseUri, String expectedClientId, JsonValue staticApiClientData) {
            super(idmBaseUri, IdmApiClientService.DEFAULT_API_CLIENT_OBJ_NAME, staticApiClientData);
            this.expectedClientId = expectedClientId;
        }

        @Override
        boolean isValidRequest(Request request) {
            final MutableUri requestUri = request.getUri();
            return request.getMethod().equals("GET")
                    && requestUri.getHost().equals(idmBaseUri.getHost())
                    && requestUri.getScheme().equals(idmBaseUri.getScheme())
                    && requestUri.getPath().equals(idmBaseUri.getPath() + "/" + expectedClientId)
                    && requestUri.getQuery().equals("_fields=apiClientOrg/*,*");
        }
    }

    public static class MockCreateApiClientIdmHandler extends BaseMockIdmResponseHandler {

        private final JsonValue expectedCreateRequestJson;

        public MockCreateApiClientIdmHandler(String idmBaseUri, JsonValue expectedCreateRequestJson, JsonValue staticApiClientData) {
            super(idmBaseUri, IdmApiClientService.DEFAULT_API_CLIENT_OBJ_NAME, staticApiClientData);
            this.expectedCreateRequestJson = expectedCreateRequestJson;
        }

        @Override
        boolean isValidRequest(Request request) {
            final MutableUri requestUri = request.getUri();
            try {
                assertJsonEquals(expectedCreateRequestJson, json(request.getEntity().getJson()));
                return request.getMethod().equals("POST")
                        && request.getHeaders().getFirst(ContentTypeHeader.class).equals(Entity.APPLICATION_JSON_CHARSET_UTF_8)
                        && requestUri.getHost().equals(idmBaseUri.getHost())
                        && requestUri.getScheme().equals(idmBaseUri.getScheme())
                        && requestUri.getPath().equals(idmBaseUri.getPath())
                        && requestUri.getQuery().equals("_fields=apiClientOrg/*,*");
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        }
    }

    public static class MockDeleteApiClientIdmHandler extends BaseMockIdmResponseHandler {

        private final String expectedClientId;

        public MockDeleteApiClientIdmHandler(String idmBaseUri, String expectedClientId, JsonValue staticApiClientData) {
            super(idmBaseUri, IdmApiClientService.DEFAULT_API_CLIENT_OBJ_NAME, staticApiClientData);
            this.expectedClientId = expectedClientId;
        }

        @Override
        boolean isValidRequest(Request request) {
            final MutableUri requestUri = request.getUri();
            // Deletes are implemented as IDM patches (POST with _action=patch), which sets the deleted field
            try {
                assertJsonEquals(json(array(object(field("operation", "replace"),
                                                   field("field", "deleted"),
                                                   field("value", true)))),
                                 json(request.getEntity().getJson()));
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
            return request.getMethod().equals("POST")
                    && request.getHeaders().getFirst(ContentTypeHeader.class).equals(Entity.APPLICATION_JSON_CHARSET_UTF_8)
                    && requestUri.getHost().equals(idmBaseUri.getHost())
                    && requestUri.getScheme().equals(idmBaseUri.getScheme())
                    && requestUri.getPath().equals(idmBaseUri.getPath() + "/" + expectedClientId)
                    && requestUriParamsAreValid(requestUri);
        }

        private static boolean requestUriParamsAreValid(MutableUri requestUri) {
            final Form queryParams = new Form().fromQueryString(requestUri.getQuery());
            final Form expectedForm = new Form();
            expectedForm.add("_action", "patch");
            expectedForm.add("_fields", "apiClientOrg/*,*");
            return queryParams.equals(expectedForm);
        }
    }

    public static class MockUpdateApiClientIdmHandler extends BaseMockIdmResponseHandler {

        private final JsonValue expectedUpdateRequestJson;

        private final String expectedClientId;

        public MockUpdateApiClientIdmHandler(String idmBaseUri, String expectedClientId,
                                             JsonValue expectedUpdateRequestJson, JsonValue staticApiClientData) {
            super(idmBaseUri, IdmApiClientService.DEFAULT_API_CLIENT_OBJ_NAME, staticApiClientData);
            this.expectedUpdateRequestJson = expectedUpdateRequestJson;
            this.expectedClientId = expectedClientId;
        }

        @Override
        boolean isValidRequest(Request request) {
            final MutableUri requestUri = request.getUri();
            try {
                assertJsonEquals(expectedUpdateRequestJson, json(request.getEntity().getJson()));
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
            return request.getMethod().equals("PUT")
                    && request.getHeaders().getFirst(ContentTypeHeader.class).equals(Entity.APPLICATION_JSON_CHARSET_UTF_8)
                    && requestUri.getHost().equals(idmBaseUri.getHost())
                    && requestUri.getScheme().equals(idmBaseUri.getScheme())
                    && requestUri.getPath().equals(idmBaseUri.getPath() + "/" + expectedClientId)
                    && requestUri.getQuery().equals("_fields=apiClientOrg/*,*");
        }
    }
}
