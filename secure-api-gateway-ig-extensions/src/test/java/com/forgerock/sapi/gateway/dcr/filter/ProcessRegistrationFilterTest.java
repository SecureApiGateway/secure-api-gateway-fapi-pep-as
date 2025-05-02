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

import static com.forgerock.sapi.gateway.dcr.filter.ProcessRegistrationFilter.rewriteUriToAccessExistingAmRegistration;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.assertj.core.api.InstanceOfAssertFactories.type;
import static org.forgerock.http.protocol.Response.newResponsePromise;
import static org.forgerock.http.protocol.Status.BAD_REQUEST;
import static org.forgerock.http.protocol.Status.CREATED;
import static org.forgerock.http.protocol.Status.OK;
import static org.forgerock.http.protocol.Status.UNAUTHORIZED;
import static org.forgerock.json.JsonValue.json;
import static org.forgerock.json.JsonValue.object;
import static org.forgerock.openig.fapi.dcr.common.ErrorCode.INVALID_SOFTWARE_STATEMENT;
import static org.forgerock.openig.fapi.dcr.common.ErrorCode.UNKNOWN;
import static org.forgerock.util.promise.Promises.newExceptionPromise;
import static org.junit.jupiter.params.provider.Arguments.arguments;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.security.cert.X509Certificate;
import java.util.stream.Stream;

import javax.imageio.IIOException;

import org.forgerock.http.Filter;
import org.forgerock.http.Handler;
import org.forgerock.http.MutableUri;
import org.forgerock.http.header.ContentTypeHeader;
import org.forgerock.http.protocol.Entity;
import org.forgerock.http.protocol.Request;
import org.forgerock.http.protocol.Response;
import org.forgerock.json.JsonValue;
import org.forgerock.json.jose.jws.SignedJwt;
import org.forgerock.openig.fapi.apiclient.ApiClient;
import org.forgerock.openig.fapi.context.FapiContext;
import org.forgerock.openig.fapi.dcr.RegistrationRequest;
import org.forgerock.openig.fapi.dcr.SoftwareStatement;
import org.forgerock.services.context.RootContext;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
public class ProcessRegistrationFilterTest {

    // ErrorResponseFactory error codes
    private static final String INVALID_CLIENT_METADATA_ERROR_CODE = "invalid_client_metadata";
    private static final String INVALID_SOFTWARE_STATEMENT_ERROR_CODE = "invalid_software_statement";
    private static final String INVALID_REDIRECT_URI_ERROR_CODE = "invalid_redirect_uri";
    // Fields
    private static final String F_REDIRECT_URIS = "redirect_uris";
    private static final String F_RESPONSE_TYPES = "response_types";
    private static final String F_TOKEN_ENDPOINT_AUTH_METHOD = "token_endpoint_auth_method";
    private static final String F_SCOPE = "scope";
    private static final String F_SOFTWARE_STATEMENT = "software_statement";

    private static final String REQUEST_URI = "https://ig.example.com/am/register/1234";
    private static final String REQUEST_URI_TRANSFORMED = "https://ig.example.com/am/register?client_id=1234";
    private static final String SSA_AS_JWT_STR = "ey123.ImASignedJwt.456";

    @Mock
    private Handler next;
    @Mock
    private ApiClient apiClient;
    @Mock
    private RegistrationRequest registrationRequest;
    @Mock
    private SoftwareStatement softwareStatement;
    @Mock
    private X509Certificate tlsClientCert;
    @Mock
    private SignedJwt ssa;

    private FapiContext fapiContext;

    @BeforeEach
    void setUp() {
        fapiContext = new FapiContext(new RootContext());
        fapiContext.setRegistrationRequest(registrationRequest);
        fapiContext.setClientCertificates(tlsClientCert);
        fapiContext.setApiClient(apiClient);
    }

    Request request(String method) {
        try {
            return new Request().setMethod(method)
                                .setUri(REQUEST_URI);
        } catch (URISyntaxException e) {
            throw new RuntimeException(e);
        }
    }

    @Test
    void shouldFailIfNoFapiContext() {
        // Given
        Filter filter = new ProcessRegistrationFilter();
        Request request = request("POST");
        // When/ Then
        assertThatThrownBy(() -> filter.filter(new RootContext(), request, next)
                                       .getOrThrowIfInterrupted())
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("FapiContext not found");
    }

    @Test
    void shouldFailIfRequestMethodUnsupported() throws IOException {
        // Given
        Filter filter = new ProcessRegistrationFilter();
        Request request = request("PATCH");
        when(registrationRequest.getSoftwareStatement()).thenReturn(softwareStatement);
        when(softwareStatement.getOrganisationId()).thenReturn("someorg");
        when(softwareStatement.getOrganisationName()).thenReturn("Some Org");
        when(softwareStatement.getSoftwareStatementAssertion()).thenReturn(ssa);
        // When/ Then
        Response response = filter.filter(fapiContext, request, next)
                                  .getOrThrowIfInterrupted();
        verifyNoInteractions(next);
        assertThat(response.getStatus()).isEqualTo(BAD_REQUEST);
        assertThat(response.getEntity().getJson())
                .asInstanceOf(type(JsonValue.class))
                .satisfies((entityJson -> {
                    assertThat(entityJson.get("error").asString())
                            .isEqualTo(UNKNOWN.getCode());
                    assertThat(entityJson.get("error_description").asString())
                            .isEqualTo("Request method 'PATCH' not supported");
                }));
    }

    @Nested
    class TestPOST {
        @Test
        void shouldCreateValidRegistration() throws IOException {
            // Given
            Filter filter = new ProcessRegistrationFilter();
            Request request = request("POST");
            when(registrationRequest.getSoftwareStatement()).thenReturn(softwareStatement);
            when(softwareStatement.getOrganisationId()).thenReturn("someorg");
            when(softwareStatement.getOrganisationName()).thenReturn("Some Org");
            when(softwareStatement.getSoftwareStatementAssertion()).thenReturn(ssa);
            when(apiClient.getSoftwareStatementAssertion()).thenReturn(ssa);
            when(ssa.build()).thenReturn(SSA_AS_JWT_STR);
            when(next.handle(fapiContext, request))
                    .thenReturn(newResponsePromise(new Response(OK).setEntity(json(object()))));
            // When
            Response response = filter.filter(fapiContext, request, next)
                                      .getOrThrowIfInterrupted();
            // Then
            verify(next).handle(fapiContext, request);
            verify(registrationRequest).setMetadata("tls_client_certificate_bound_access_tokens", true);
            assertThat(response.getStatus()).isEqualTo(OK);
            assertThat(response.getEntity().getJson())
                    .asInstanceOf(type(JsonValue.class))
                    .satisfies(jsonValue -> {
                        assertThat(jsonValue.get(F_SOFTWARE_STATEMENT).asString()).isEqualTo(SSA_AS_JWT_STR);
                    });
        }

        @Test
        void shouldFailOnInvalidRegistrationResponseJson() throws IOException {
            // Given
            Filter filter = new ProcessRegistrationFilter();
            Request request = request("POST");
            when(registrationRequest.getSoftwareStatement()).thenReturn(softwareStatement);
            when(softwareStatement.getOrganisationId()).thenReturn("someorg");
            when(softwareStatement.getOrganisationName()).thenReturn("Some Org");
            when(softwareStatement.getSoftwareStatementAssertion()).thenReturn(ssa);
            when(apiClient.getSoftwareStatementAssertion()).thenReturn(ssa);
            when(ssa.build()).thenReturn(SSA_AS_JWT_STR);
            // ... and - getting response entity JSON raises an IOException
            Response invalidJsonResponse = new Response(OK).addHeaders(ContentTypeHeader.valueOf("application/json"));
            invalidJsonResponse.getEntity()
                               .setString("{ \"field1\": \"value\", \"field2\": invalid }");
            when(next.handle(fapiContext, request))
                     .thenReturn(newResponsePromise(invalidJsonResponse));
            // When
            Response response = filter.filter(fapiContext, request, next)
                                      .getOrThrowIfInterrupted();
            // Then
            verify(next).handle(fapiContext, request);
            verify(registrationRequest).setMetadata("tls_client_certificate_bound_access_tokens", true);
            assertThat(response.getStatus()).isEqualTo(BAD_REQUEST);
            assertThat(response.getEntity().getJson())
                    .asInstanceOf(type(JsonValue.class))
                    .satisfies((entityJson -> {
                        assertThat(entityJson.get("error").asString())
                                .isEqualTo(UNKNOWN.getCode());
                        assertThat(entityJson.get("error_description").asString())
                                .isEqualTo("Error transforming response JSON");
                    }));
        }

        @Test
        void shouldNotAddSsaToResponseOnFailedRegistration() throws IOException {
            // Given
            Filter filter = new ProcessRegistrationFilter();
            Request request = request("POST");
            when(registrationRequest.getSoftwareStatement()).thenReturn(softwareStatement);
            when(softwareStatement.getOrganisationId()).thenReturn("someorg");
            when(softwareStatement.getOrganisationName()).thenReturn("Some Org");
            when(softwareStatement.getSoftwareStatementAssertion()).thenReturn(ssa);
            when(ssa.build()).thenReturn(SSA_AS_JWT_STR);
            when(next.handle(fapiContext, request))
                    .thenReturn(newResponsePromise(new Response(UNAUTHORIZED)));
            // When
            Response response = filter.filter(fapiContext, request, next)
                                      .getOrThrowIfInterrupted();
            // Then - Response entity does not contain augmented 'software_statement' JSON (have to read as String)
            verify(next).handle(fapiContext, request);
            verify(registrationRequest).setMetadata("tls_client_certificate_bound_access_tokens", true);
            assertThat(response.getStatus()).isEqualTo(UNAUTHORIZED);
            assertThat(response.getEntity().getString()).doesNotContain(F_SOFTWARE_STATEMENT);
        }
    }

    @Nested
    class TestPut {
        @Test
        void shouldUpdateValidRegistration() throws IOException {
            // Given
            Filter filter = new ProcessRegistrationFilter();
            Request request = request("PUT");
            when(registrationRequest.getSoftwareStatement()).thenReturn(softwareStatement);
            when(softwareStatement.getOrganisationId()).thenReturn("someorg");
            when(softwareStatement.getOrganisationName()).thenReturn("Some Org");
            when(softwareStatement.getSoftwareStatementAssertion()).thenReturn(ssa);
            when(apiClient.getSoftwareStatementAssertion()).thenReturn(ssa);
            when(ssa.build()).thenReturn(SSA_AS_JWT_STR);
            when(next.handle(fapiContext, request))
                     .thenReturn(newResponsePromise(new Response(OK).setEntity(json(object()))));
            // When
            Response response = filter.filter(fapiContext, request, next)
                                      .getOrThrowIfInterrupted();
            // Then
            verify(next).handle(fapiContext, request);
            verify(registrationRequest).setMetadata("tls_client_certificate_bound_access_tokens", true);            assertThat(response.getStatus()).isEqualTo(OK);
            assertThat(request.getUri().toString()).isEqualTo(REQUEST_URI_TRANSFORMED);
            assertThat(response.getEntity().getJson())
                    .asInstanceOf(type(JsonValue.class))
                    .satisfies(jsonValue -> {
                        assertThat(jsonValue.get(F_SOFTWARE_STATEMENT).asString()).isEqualTo(SSA_AS_JWT_STR);
                    });
        }
    }

    @Nested
    class TestGet {
        @Test
        void shouldGetRegistration() throws IOException {
            // Given
            Filter filter = new ProcessRegistrationFilter();
            Request request = request("GET");
            when(registrationRequest.getSoftwareStatement()).thenReturn(softwareStatement);
            when(softwareStatement.getOrganisationId()).thenReturn("someorg");
            when(softwareStatement.getOrganisationName()).thenReturn("Some Org");
            when(softwareStatement.getSoftwareStatementAssertion()).thenReturn(ssa);
            when(apiClient.getSoftwareStatementAssertion()).thenReturn(ssa);
            when(ssa.build()).thenReturn(SSA_AS_JWT_STR);
            when(next.handle(fapiContext, request))
                    .thenReturn(newResponsePromise(new Response(OK).setEntity(json(object()))));
            // When
            Response response = filter.filter(fapiContext, request, next)
                                      .getOrThrowIfInterrupted();
            // Then
            verify(next).handle(fapiContext, request);
            assertThat(request.getUri().toString()).isEqualTo(REQUEST_URI_TRANSFORMED);
            assertThat(response.getStatus()).isEqualTo(OK);
            assertThat(response.getEntity().getJson())
                    .asInstanceOf(type(JsonValue.class))
                    .satisfies(jsonValue -> {
                        assertThat(jsonValue.get(F_SOFTWARE_STATEMENT).asString()).isEqualTo(SSA_AS_JWT_STR);
                    });
        }
    }

    @Nested
    class TestDelete {
        @Test
        void shouldDeleteRegistration() throws IOException {
            // Given
            Filter filter = new ProcessRegistrationFilter();
            Request request = request("DELETE");
            when(registrationRequest.getSoftwareStatement()).thenReturn(softwareStatement);
            when(softwareStatement.getOrganisationId()).thenReturn("someorg");
            when(softwareStatement.getOrganisationName()).thenReturn("Some Org");
            when(softwareStatement.getSoftwareStatementAssertion()).thenReturn(ssa);
            when(ssa.build()).thenReturn(SSA_AS_JWT_STR);
            when(next.handle(fapiContext, request))
                    .thenReturn(newResponsePromise(new Response(OK).setEntity(json(object()))));
            // When
            Response response = filter.filter(fapiContext, request, next)
                                      .getOrThrowIfInterrupted();
            // Then
            verify(next).handle(fapiContext, request);
            assertThat(response.getStatus()).isEqualTo(OK);
            assertThat(request.getUri().toString()).isEqualTo(REQUEST_URI_TRANSFORMED);
            assertThat(response.getEntity().getJson())
                    .asInstanceOf(type(JsonValue.class))
                    .satisfies(jsonValue -> {
                        assertThat(jsonValue.isDefined(F_SOFTWARE_STATEMENT)).isFalse();
                    });
        }
    }

    @Nested
    class UriTransformations {
        static Stream<Arguments> uriTransformations() {
            return Stream.of(
                    arguments("https://a.b.c/1234", "https://a.b.c?client_id=1234"),
                    arguments("https://a.b.c/register/1234", "https://a.b.c/register?client_id=1234")
            );
        }

        @ParameterizedTest
        @MethodSource("uriTransformations")
        void shouldRewriteUriRestParamToQueryParam(final String sourceUri, final String transformedUri) {
            Request request = new Request().setUri(URI.create(sourceUri));
            rewriteUriToAccessExistingAmRegistration(request);
            assertThat(request.getUri().toString()).isEqualTo(transformedUri);
        }

        @Test
        void shouldFailToRewriteUriRestParamToQueryParamIfNoPath() {
            Request request = new Request().setUri(URI.create("https://a.b.c"));
            assertThatThrownBy(() -> rewriteUriToAccessExistingAmRegistration(request))
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessage("API Client ID path parameter not found");
        }

        @Test
        void shouldFailToRewriteUriRestParamToQueryParamIfUriInvalid() throws URISyntaxException {
            // Given
            Request request = mock(Request.class);
            MutableUri uri = mock(MutableUri.class);
            when(request.getUri()).thenReturn(uri);
            when(uri.getPath()).thenReturn("/1234");
            doThrow(new URISyntaxException("KA", "BOOM")).when(uri).setRawPath(any());
            // When/ Then
            assertThatThrownBy(() -> rewriteUriToAccessExistingAmRegistration(request))
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessage("API Client ID path parameter not found");
        }
    }
}
