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

import static com.forgerock.sapi.gateway.util.JsonUtils.assertJsonEquals;
import static org.assertj.core.api.Assertions.assertThat;
import static org.forgerock.json.JsonValue.field;
import static org.forgerock.json.JsonValue.json;
import static org.forgerock.json.JsonValue.object;
import static org.forgerock.util.promise.Promises.newResultPromise;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.when;

import java.io.IOException;
import java.util.UUID;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.stream.Stream;

import org.forgerock.http.Client;
import org.forgerock.http.Handler;
import org.forgerock.http.MutableUri;
import org.forgerock.http.header.ContentTypeHeader;
import org.forgerock.http.protocol.Entity;
import org.forgerock.http.protocol.Request;
import org.forgerock.http.protocol.Response;
import org.forgerock.http.protocol.Status;
import org.forgerock.json.JsonValue;
import org.forgerock.openig.handler.Handlers;
import org.forgerock.util.promise.Promise;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.Mockito;

import com.forgerock.sapi.gateway.dcr.models.ApiClientOrganisation;
import com.forgerock.sapi.gateway.dcr.models.SoftwareStatement;
import com.forgerock.sapi.gateway.dcr.service.ApiClientServiceException;
import com.forgerock.sapi.gateway.dcr.service.ApiClientServiceException.ErrorCode;

class IdmApiClientOrganisationServiceTest {

    private static final String ORG_ID = UUID.randomUUID().toString();
    private static final String ORG_NAME = "Acme Fintech";
    public static final SoftwareStatement SOFTWARE_STATEMENT = createMockSoftwareStatement(ORG_ID, ORG_NAME);
    public static final JsonValue EXPECTED_CREATE_REQUEST_JSON = json(object(field("_id", ORG_ID),
                                                                             field("id", ORG_ID),
                                                                             field("name", ORG_NAME)));
    public static final String IDM_BASE_URI = "http://idm/managed/object";

    @Test
    void testCreatingNewApiClientOrganisation() throws Exception {
        final MockCreateApiClientOrganisationIdmHandler idmResponseHandler =
                new MockCreateApiClientOrganisationIdmHandler(IDM_BASE_URI, ORG_ID, EXPECTED_CREATE_REQUEST_JSON, Status.CREATED);

        testCreateApiClientOrganisation(idmResponseHandler);
    }

    private static void testCreateApiClientOrganisation(MockCreateApiClientOrganisationIdmHandler idmResponseHandler) throws InterruptedException, ApiClientServiceException, TimeoutException {
        final IdmApiClientOrganisationService service = new IdmApiClientOrganisationService(new Client(idmResponseHandler), IDM_BASE_URI);

        final Promise<ApiClientOrganisation, ApiClientServiceException> apiClientOrganisationPromise =
                service.createApiClientOrganisation(SOFTWARE_STATEMENT);

        final ApiClientOrganisation apiClientOrganisation = apiClientOrganisationPromise.getOrThrow(1, TimeUnit.MILLISECONDS);
        assertThat(apiClientOrganisation.id()).isEqualTo(ORG_ID);
        assertThat(apiClientOrganisation.name()).isEqualTo(ORG_NAME);
    }

    private static SoftwareStatement createMockSoftwareStatement(String orgId, String orgName) {
        final SoftwareStatement softwareStatement = Mockito.mock(SoftwareStatement.class);
        when(softwareStatement.getOrgId()).thenReturn(orgId);
        when(softwareStatement.getOrgName()).thenReturn(orgName);
        return softwareStatement;
    }

    @Test
    void testCreatingApiClientOrganisationThatExists() throws Exception {
        // Return 412 Pre Condition Failed response
        final MockCreateApiClientOrganisationIdmHandler idmResponseHandler =
                new MockCreateApiClientOrganisationIdmHandler(IDM_BASE_URI, ORG_ID, EXPECTED_CREATE_REQUEST_JSON, Status.valueOf(412));

        testCreateApiClientOrganisation(idmResponseHandler);
    }

    @ParameterizedTest
    @MethodSource(value = "failsWithExceptionWhenIdmReturnsErrorStatusResponseArguments")
    void failsWithExceptionWhenIdmReturnsErrorStatusResponse(Status status) {
        final Handler responseHandler = (ctxt, req) -> newResultPromise(new Response(status));
        final IdmApiClientOrganisationService service = new IdmApiClientOrganisationService(new Client(responseHandler), IDM_BASE_URI);

        final ApiClientServiceException exception = assertThrows(ApiClientServiceException.class,
                () -> service.createApiClientOrganisation(SOFTWARE_STATEMENT).getOrThrow(1, TimeUnit.MILLISECONDS));
        assertThat(exception.getErrorCode()).isEqualTo(ErrorCode.SERVER_ERROR);
        assertThat(exception.getMessage()).startsWith("[SERVER_ERROR] Unexpected IDM response:");
    }

    static Stream<Arguments> failsWithExceptionWhenIdmReturnsErrorStatusResponseArguments() {
        return Stream.of(Status.BAD_REQUEST, Status.FORBIDDEN, Status.UNAUTHORIZED, Status.INTERNAL_SERVER_ERROR)
                     .map(Arguments::of);
    }

    @ParameterizedTest
    @ValueSource(strings = {IDM_BASE_URI, IDM_BASE_URI + "/"})
    void shouldRemoveTrailingSlashInIdmBaseUri(String baseUri) {
        final IdmApiClientOrganisationService service = new IdmApiClientOrganisationService(new Client(Handlers.FORBIDDEN), baseUri);

        assertEquals("http://idm/managed/object/apiClientOrg/" + ORG_ID,
                     service.buildApiClientOrgUri(ORG_ID).toString());
    }

    public static class MockCreateApiClientOrganisationIdmHandler extends BaseMockIdmResponseHandler {

        private final String expectedOrgId;

        private final JsonValue expectedCreateRequestJson;

        private final Status responseStatus;

        public MockCreateApiClientOrganisationIdmHandler(String idmBaseUri, String expectedOrgId,
                                                         JsonValue expectedCreateRequestJson, Status idmResponseStatus) {
            super(idmBaseUri, IdmApiClientOrganisationService.DEFAULT_API_CLIENT_ORG_OBJ_NAME, json(object()));
            this.expectedOrgId = expectedOrgId;
            this.expectedCreateRequestJson = expectedCreateRequestJson;
            this.responseStatus = idmResponseStatus;
        }

        @Override
        protected Response customiseResponse(Response response) {
            return response.setStatus(responseStatus);
        }

        @Override
        boolean isValidRequest(Request request) {
            final MutableUri requestUri = request.getUri();
            try {
                assertJsonEquals(expectedCreateRequestJson, json(request.getEntity().getJson()));
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
            return request.getMethod().equals("PUT")
                    && requestUri.toString().equals(idmBaseUri + "/" + expectedOrgId)
                    && request.getHeaders().getFirst(ContentTypeHeader.class).equals(Entity.APPLICATION_JSON_CHARSET_UTF_8)
                    && request.getHeaders().getFirst("If-None-Match").equals("*");
        }
    }
}