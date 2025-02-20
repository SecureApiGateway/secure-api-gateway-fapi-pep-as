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
package com.forgerock.sapi.gateway.scripts;

import static com.forgerock.sapi.gateway.util.CryptoUtils.createJwkForCert;
import static com.forgerock.sapi.gateway.util.CryptoUtils.generateRsaKeyPair;
import static com.forgerock.sapi.gateway.util.CryptoUtils.generateX509Cert;
import static java.util.Collections.emptyList;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.InstanceOfAssertFactories.type;
import static org.forgerock.http.protocol.Response.newResponsePromise;
import static org.forgerock.http.protocol.Status.BAD_REQUEST;
import static org.forgerock.http.protocol.Status.INTERNAL_SERVER_ERROR;
import static org.forgerock.http.protocol.Status.OK;
import static org.forgerock.json.JsonValue.array;
import static org.forgerock.json.JsonValue.field;
import static org.forgerock.json.JsonValue.json;
import static org.forgerock.json.JsonValue.object;
import static org.forgerock.util.promise.Promises.newResultPromise;
import static org.junit.jupiter.params.provider.Arguments.arguments;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import java.net.URI;
import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.regex.Pattern;
import java.util.stream.Stream;

import org.forgerock.http.Filter;
import org.forgerock.http.Handler;
import org.forgerock.http.protocol.Request;
import org.forgerock.http.protocol.Response;
import org.forgerock.json.JsonValue;
import org.forgerock.json.jose.jwk.JWKSet;
import org.forgerock.json.jose.jws.SignedJwt;
import org.forgerock.openig.fapi.apiclient.ApiClient;
import org.forgerock.openig.fapi.apiclient.ApiClientOrganisation;
import org.forgerock.openig.fapi.dcr.RegistrationRequest;
import org.forgerock.openig.fapi.dcr.SoftwareStatement;
import org.forgerock.openig.fapi.jwks.JwkSetService;
import org.forgerock.openig.fapi.trusteddirectory.TrustedDirectoryService;
import org.forgerock.openig.filter.ScriptableFilter;
import org.forgerock.openig.heap.HeapImpl;
import org.forgerock.openig.heap.Name;
import org.forgerock.openig.util.Choice;
import org.forgerock.services.context.AttributesContext;
import org.forgerock.services.context.RootContext;
import org.forgerock.util.Pair;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.KeyUse;

/**
 * Unit test for {@code ProcessRegistration} script.
 */
@ExtendWith(MockitoExtension.class)
class ProcessRegistrationTest extends AbstractScriptTest {
    // Untested:
    // - DELETE methods
    // - subject
    // - generally more coverage required

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
    // Values
    private static final String API_CLIENT_ID = "1234";
    private static final String DN = "CN=fapitest";
    private static final URI JWKS_URI = URI.create("https://www.fintech.com/jwks");
    private static final URI REDIRECT_URI = URI.create("https://www.fintech.com/redirect");
    private static final URI REQUEST_URI = URI.create("https://www.bank.com/" + API_CLIENT_ID);
    private static final String RESPONSE_TYPE = "code id_token";
    private static final String SSA_AS_JWT_STR = "ey123.ImASignedJwt.456";

    private static JWKSet jwkSet;
    private static X509Certificate testTlsCert;

    @Mock
    private Handler next;
    @Mock
    private JwkSetService jwkSetService;
    @Mock
    private TrustedDirectoryService trustedDirectoryService;
    @Mock
    private RegistrationRequest registrationRequest;
    @Mock
    private SoftwareStatement softwareStatement;
    @Mock
    private SignedJwt ssa;

    private AttributesContext attributesContext;

    @BeforeAll
    public static void setUpSecrets() throws JOSEException {
        Pair<X509Certificate, JWKSet> pair = generateKeyCertAndJwks();
        testTlsCert = pair.getFirst();
        jwkSet = pair.getSecond();
    }

    @BeforeEach
    public void setUpContext() {
        attributesContext = new AttributesContext(new RootContext());
    }

    protected HeapImpl getHeap() throws Exception {
        final HeapImpl heap = super.getHeap();
        heap.put("JwkSetService", jwkSetService);
        heap.put("TrustedDirectoryService", trustedDirectoryService);
        return heap;
    }

    @Nested
    class TestPOST {
        @Test
        void shouldProcessValidRegistration() throws Exception {
            // Given
            // ... registrationRequest content
            when(registrationRequest.getResponseTypes()).thenReturn(List.of(RESPONSE_TYPE));
            when(registrationRequest.getTokenEndpointAuthMethod()).thenReturn("tls_client_auth");
            when(registrationRequest.getMetadata(eq("tls_client_auth_subject_dn"))).thenReturn(new JsonValue(DN));
            when(registrationRequest.getMetadata("subject_type")).thenReturn(new JsonValue("pairwise"));
            when(registrationRequest.getSoftwareStatement()).thenReturn(softwareStatement);
            when(softwareStatement.getOrganisationId()).thenReturn("someorg");
            when(softwareStatement.getOrganisationName()).thenReturn("Some Org");
            when(softwareStatement.getJwkSetLocator()).thenReturn(Choice.withValue2(jwkSet));
            doAnswer(invocation -> null)
                    .when(registrationRequest).setMetadata("tls_client_certificate_bound_access_tokens", true);
            doAnswer(invocation -> null)
                    .when(registrationRequest).setMetadata(eq("jwks"), any());
            // ... registrationRequest validation
            when(registrationRequest.getScope()).thenReturn("accounts");
            when(softwareStatement.getRoles()).thenReturn(List.of("AISP"));
            when(registrationRequest.getRedirectUris()).thenReturn(List.of(REDIRECT_URI));
            when(softwareStatement.getRedirectUris()).thenReturn(List.of(REDIRECT_URI));
            when(softwareStatement.getSoftwareStatementAssertion()).thenReturn(ssa);
            when(ssa.build()).thenReturn(SSA_AS_JWT_STR);
            // ... on next
            when(registrationRequest.toJsonValue())
                    .thenReturn(json(object(field(F_SCOPE, "accounts"),
                                            field(F_RESPONSE_TYPES, array(RESPONSE_TYPE)),
                                            field(F_TOKEN_ENDPOINT_AUTH_METHOD, "tls_client_auth"),
                                            field(F_REDIRECT_URIS, array(REDIRECT_URI.toString())))));
            Request request = new Request().setMethod("POST").setUri(REQUEST_URI);
            when(next.handle(attributesContext, request))
                    .thenReturn(newResponsePromise(new Response(OK).setEntity(json(object()))));
            // ... filter and context
            JsonValue config = validProcessRegistrationConfig();
            Filter filter = (Filter) new ScriptableFilter.Heaplet()
                    .create(Name.of("ProcessRegistration"), config, getHeap());
            attributesContext.getAttributes().put("registrationRequest", registrationRequest);
            attributesContext.getAttributes().put("clientCertificate", testTlsCert);
            // When
            final Response response = filter.filter(attributesContext, request, next).get();
            // Then
            assertThat(response.getStatus()).isEqualTo(OK);
            assertThat(response.getEntity().getJson())
                    .asInstanceOf(type(JsonValue.class))
                    .satisfies(jsonValue -> {
                        assertThat(jsonValue.get(F_SOFTWARE_STATEMENT).asString())
                                .isEqualTo(SSA_AS_JWT_STR);
                    });
            verify(next).handle(attributesContext, request);
            verify(registrationRequest).setMetadata("tls_client_certificate_bound_access_tokens", true);
            verify(registrationRequest).setMetadata(eq("jwks"), any());  // can't verify eq(jwkSet)
        }

        @Test
        void shouldProcessValidRegistrationWithJwkSetSupplier() throws Exception {
            // Given
            // ... registrationRequest content
            when(registrationRequest.getResponseTypes()).thenReturn(List.of(RESPONSE_TYPE));
            when(registrationRequest.getTokenEndpointAuthMethod()).thenReturn("tls_client_auth");
            when(registrationRequest.getMetadata(eq("tls_client_auth_subject_dn"))).thenReturn(new JsonValue(DN));
            when(registrationRequest.getMetadata("subject_type")).thenReturn(new JsonValue("pairwise"));
            when(registrationRequest.getSoftwareStatement()).thenReturn(softwareStatement);
            when(softwareStatement.getOrganisationId()).thenReturn("someorg");
            when(softwareStatement.getOrganisationName()).thenReturn("Some Org");
            when(softwareStatement.getJwkSetLocator()).thenReturn(Choice.withValue1(JWKS_URI));
            when(jwkSetService.getJwkSet(any())).thenReturn(newResultPromise(jwkSet));
            doAnswer(invocation -> null)
                    .when(registrationRequest).setMetadata("tls_client_certificate_bound_access_tokens", true);
            doAnswer(invocation -> null)
                    .when(registrationRequest).setMetadata("jwks_uri", JWKS_URI.toASCIIString());
            // ... registrationRequest validation
            when(registrationRequest.getScope()).thenReturn("accounts");
            when(softwareStatement.getRoles()).thenReturn(List.of("AISP"));
            when(registrationRequest.getRedirectUris()).thenReturn(List.of(REDIRECT_URI));
            when(softwareStatement.getRedirectUris()).thenReturn(List.of(REDIRECT_URI));
            when(softwareStatement.getSoftwareStatementAssertion()).thenReturn(ssa);
            when(ssa.build()).thenReturn(SSA_AS_JWT_STR);
            // ... on next
            when(registrationRequest.toJsonValue())
                    .thenReturn(json(object(field(F_SCOPE, "accounts"),
                                            field(F_RESPONSE_TYPES, array(RESPONSE_TYPE)),
                                            field(F_TOKEN_ENDPOINT_AUTH_METHOD, "tls_client_auth"),
                                            field(F_REDIRECT_URIS, array(REDIRECT_URI.toString())))));
            Request request = new Request().setMethod("POST").setUri(REQUEST_URI);
            when(next.handle(attributesContext, request))
                    .thenReturn(newResponsePromise(new Response(OK).setEntity(json(object()))));
            // ... filter and context
            JsonValue config = validProcessRegistrationConfig();
            Filter filter = (Filter) new ScriptableFilter.Heaplet()
                    .create(Name.of("ProcessRegistration"), config, getHeap());
            attributesContext.getAttributes().put("registrationRequest", registrationRequest);
            attributesContext.getAttributes().put("clientCertificate", testTlsCert);
            // When
            final Response response = filter.filter(attributesContext, request, next).get();
            // Then
            assertThat(response.getStatus()).isEqualTo(OK);
            assertThat(response.getEntity().getJson())
                    .asInstanceOf(type(JsonValue.class))
                    .satisfies(jsonValue -> {
                        assertThat(jsonValue.get(F_SOFTWARE_STATEMENT).asString())
                                .isEqualTo(SSA_AS_JWT_STR);
                    });
            verify(next).handle(attributesContext, request);
            verify(registrationRequest).setMetadata("tls_client_certificate_bound_access_tokens", true);
            verify(registrationRequest).setMetadata("jwks_uri", JWKS_URI.toASCIIString());
        }

        @Test
        void shouldRejectMissingRegistrationRequest() throws Exception {
            // Given
            final JsonValue config = validProcessRegistrationConfig();
            Filter filter = (Filter) new ScriptableFilter.Heaplet()
                    .create(Name.of("ProcessRegistration"), config, getHeap());
            Request request = new Request().setMethod("POST").setUri(REQUEST_URI);
            // When
            final Response response = filter.filter(attributesContext, request, next).get();
            // Then
            assertThat(response.getStatus()).isEqualTo(INTERNAL_SERVER_ERROR);
            assertThat(response.getEntity().getBytes()).isEmpty();
            verifyNoInteractions(next);
        }

        @Test
        void shouldRejectMissingClientCertificate() throws Exception {
            // Given
            final JsonValue config = validProcessRegistrationConfig();
            Filter filter = (Filter) new ScriptableFilter.Heaplet()
                    .create(Name.of("ProcessRegistration"), config, getHeap());
            Request request = new Request().setMethod("POST").setUri(REQUEST_URI);
            attributesContext.getAttributes().put("registrationRequest", registrationRequest);
            // When
            final Response response = filter.filter(attributesContext, request, next).get();
            // Then
            assertThat(response.getStatus()).isEqualTo(BAD_REQUEST);
            assertThat(response.getEntity().getJson())
                    .asInstanceOf(type(JsonValue.class))
                    .satisfies(jsonValue -> {
                        assertThat(jsonValue.get("error").asString()).isEqualTo(INVALID_CLIENT_METADATA_ERROR_CODE);
                        assertThat(jsonValue.get("error_description").asString())
                                .isEqualTo("No client certificate for registration");
                    });
            verifyNoInteractions(next);
        }

        @Test
        void shouldRejectMissingTokenEndpointAuthMethod() throws Exception {
            // Given
            // ... registrationRequest content
            when(registrationRequest.getResponseTypes()).thenReturn(List.of(RESPONSE_TYPE));
            when(registrationRequest.getTokenEndpointAuthMethod()).thenReturn(null);
            // ... filter and context
            final JsonValue config = validProcessRegistrationConfig();
            Filter filter = (Filter) new ScriptableFilter.Heaplet()
                    .create(Name.of("ProcessRegistration"), config, getHeap());
            Request request = new Request().setMethod("POST").setUri(REQUEST_URI);
            attributesContext.getAttributes().put("registrationRequest", registrationRequest);
            attributesContext.getAttributes().put("clientCertificate", testTlsCert);
            // When
            final Response response = filter.filter(attributesContext, request, next).get();
            // Then
            assertThat(response.getStatus()).isEqualTo(BAD_REQUEST);
            assertThat(response.getEntity().getJson())
                    .asInstanceOf(type(JsonValue.class))
                    .satisfies(jsonValue -> {
                        assertThat(jsonValue.get("error").asString()).isEqualTo(INVALID_CLIENT_METADATA_ERROR_CODE);
                        assertThat(jsonValue.get("error_description").asString())
                                .isEqualTo("token_endpoint_auth_method claim must be one of: [tls_client_auth]");
                    });
            verifyNoInteractions(next);
        }

        @Test
        void shouldRejectTokenEndpointAuthMethodWithMissingDn() throws Exception {
            // Given
            // ... registrationRequest content
            when(registrationRequest.getResponseTypes()).thenReturn(List.of(RESPONSE_TYPE));
            when(registrationRequest.getTokenEndpointAuthMethod()).thenReturn("tls_client_auth");
            when(registrationRequest.getMetadata(eq("tls_client_auth_subject_dn"))).thenReturn(json(null));
            // ... filter and context
            final JsonValue config = validProcessRegistrationConfig();
            Filter filter = (Filter) new ScriptableFilter.Heaplet()
                    .create(Name.of("ProcessRegistration"), config, getHeap());
            Request request = new Request().setMethod("POST").setUri(REQUEST_URI);
            attributesContext.getAttributes().put("registrationRequest", registrationRequest);
            attributesContext.getAttributes().put("clientCertificate", testTlsCert);
            // When
            final Response response = filter.filter(attributesContext, request, next).get();
            // Then
            assertThat(response.getStatus()).isEqualTo(BAD_REQUEST);
            assertThat(response.getEntity().getJson())
                    .asInstanceOf(type(JsonValue.class))
                    .satisfies(jsonValue -> {
                        assertThat(jsonValue.get("error").asString()).isEqualTo(INVALID_CLIENT_METADATA_ERROR_CODE);
                        assertThat(jsonValue.get("error_description").asString())
                                .isEqualTo("tls_client_auth_subject_dn must be provided to use tls_client_auth");
                    });
            verifyNoInteractions(next);
        }

        private static Stream<Arguments> invalidRegistrationRedirectUris() {
            return Stream.of(
                    // "http" scheme is not allowed
                    arguments(List.of(URI.create("http://www.example.com/redirect")),
                              Pattern.compile("invalid registration request redirect_uris value: .* must use https")),
                    // "localhost" is not allowed
                    arguments(List.of(URI.create("https://localhost/redirect")),
                              Pattern.compile("invalid .* redirect_uris .* must not point to localhost")),
                    // unregistererd (SSA) redirect URI is not allowed
                    arguments(List.of(URI.create("https://www.unknown.com/redirect")),
                              Pattern.compile(".* must match or be a subset of the software_redirect_uris"))
            );
        }

        @ParameterizedTest
        @MethodSource("invalidRegistrationRedirectUris")
        void shouldRejectInvalidRedirectUri(final List<URI> registrationRedirectUri,
                                            final Pattern expectedErrorPattern) throws Exception {
            // Given
            // ... registrationRequest content
            when(registrationRequest.getResponseTypes()).thenReturn(List.of(RESPONSE_TYPE));
            when(registrationRequest.getTokenEndpointAuthMethod()).thenReturn("tls_client_auth");
            when(registrationRequest.getMetadata(eq("tls_client_auth_subject_dn"))).thenReturn(new JsonValue(DN));
            when(registrationRequest.getMetadata("subject_type")).thenReturn(new JsonValue("pairwise"));
            when(registrationRequest.getSoftwareStatement()).thenReturn(softwareStatement);
            when(softwareStatement.getOrganisationId()).thenReturn("someorg");
            when(softwareStatement.getOrganisationName()).thenReturn("Some Org");
            // ... registrationRequest validation
            when(registrationRequest.getScope()).thenReturn("accounts");
            when(softwareStatement.getRoles()).thenReturn(List.of("AISP"));
            when(registrationRequest.getRedirectUris()).thenReturn(registrationRedirectUri);
            when(softwareStatement.getRedirectUris()).thenReturn(List.of(REDIRECT_URI));
            when(softwareStatement.getSoftwareStatementAssertion()).thenReturn(ssa);
            when(ssa.build()).thenReturn(SSA_AS_JWT_STR);
            // ... filter and context
            final JsonValue config = validProcessRegistrationConfig();
            Filter filter = (Filter) new ScriptableFilter.Heaplet()
                    .create(Name.of("ProcessRegistration"), config, getHeap());
            Request request = new Request().setMethod("POST").setUri(REQUEST_URI);
            attributesContext.getAttributes().put("registrationRequest", registrationRequest);
            attributesContext.getAttributes().put("clientCertificate", testTlsCert);
            // When
            final Response response = filter.filter(attributesContext, request, next).get();
            // Then
            assertThat(response.getStatus()).isEqualTo(BAD_REQUEST);
            assertThat(response.getEntity().getJson())
                    .asInstanceOf(type(JsonValue.class))
                    .satisfies(jsonValue -> {
                        assertThat(jsonValue.get("error").asString()).isEqualTo(INVALID_REDIRECT_URI_ERROR_CODE);
                        assertThat(jsonValue.get("error_description").asString())
                                .matches(expectedErrorPattern);
                    });
            verifyNoInteractions(next);
        }

        @Test
        void shouldPreventIgTestCerts() throws Exception {
            // Given
            // ... registrationRequest content
            when(registrationRequest.getResponseTypes()).thenReturn(List.of(RESPONSE_TYPE));
            when(registrationRequest.getTokenEndpointAuthMethod()).thenReturn("tls_client_auth");
            when(registrationRequest.getMetadata(eq("tls_client_auth_subject_dn"))).thenReturn(new JsonValue(DN));
            when(registrationRequest.getMetadata("subject_type")).thenReturn(new JsonValue("pairwise"));
            when(registrationRequest.getSoftwareStatement()).thenReturn(softwareStatement);
            when(softwareStatement.getOrganisationId()).thenReturn("someorg");
            when(softwareStatement.getOrganisationName()).thenReturn("Some Org");
            when(softwareStatement.getJwkSetLocator()).thenReturn(Choice.withValue2(jwkSet));
            // ... registrationRequest validation
            when(registrationRequest.getScope()).thenReturn("accounts");
            when(softwareStatement.getRoles()).thenReturn(List.of("AISP"));
            when(registrationRequest.getRedirectUris()).thenReturn(List.of(REDIRECT_URI));
            when(softwareStatement.getRedirectUris()).thenReturn(List.of(REDIRECT_URI));
            when(softwareStatement.getSoftwareStatementAssertion()).thenReturn(ssa);
            when(ssa.build()).thenReturn(SSA_AS_JWT_STR);
            // ... filter and context
            final JsonValue config = validProcessRegistrationConfigPreventIgTestCerts();
            Filter filter = (Filter) new ScriptableFilter.Heaplet()
                    .create(Name.of("ProcessRegistration"), config, getHeap());
            Request request = new Request().setMethod("POST").setUri(REQUEST_URI);
            attributesContext.getAttributes().put("registrationRequest", registrationRequest);
            attributesContext.getAttributes().put("clientCertificate", testTlsCert);
            // When
            final Response response = filter.filter(attributesContext, request, next).get();
            // Then
            assertThat(response.getStatus()).isEqualTo(BAD_REQUEST);
            assertThat(response.getEntity().getJson())
                    .asInstanceOf(type(JsonValue.class))
                    .satisfies(jsonValue -> {
                        assertThat(jsonValue.get("error").asString()).isEqualTo(INVALID_CLIENT_METADATA_ERROR_CODE);
                        assertThat(jsonValue.get("error_description").asString())
                                .isEqualTo("software_statement must contain software_jwks_endpoint");
                    });
            verifyNoInteractions(next);
        }

        @Test
        void shouldUseDefaultResponseTypesIfNotProvided() throws Exception {
            // Given
            // ... registrationRequest content
            when(registrationRequest.getResponseTypes()).thenReturn(emptyList());
            when(registrationRequest.getTokenEndpointAuthMethod()).thenReturn("tls_client_auth");
            when(registrationRequest.getMetadata(eq("tls_client_auth_subject_dn"))).thenReturn(new JsonValue(DN));
            when(registrationRequest.getMetadata("subject_type")).thenReturn(new JsonValue("pairwise"));
            when(registrationRequest.getSoftwareStatement()).thenReturn(softwareStatement);
            when(softwareStatement.getOrganisationId()).thenReturn("someorg");
            when(softwareStatement.getOrganisationName()).thenReturn("Some Org");
            when(softwareStatement.getJwkSetLocator()).thenReturn(Choice.withValue2(jwkSet));
            doAnswer(invocation -> null)
                    .when(registrationRequest).setMetadata("tls_client_certificate_bound_access_tokens", true);
            doAnswer(invocation -> null)
                    .when(registrationRequest).setResponseTypes(List.of(RESPONSE_TYPE));
            // ... registrationRequest validation
            when(registrationRequest.getScope()).thenReturn("accounts");
            when(softwareStatement.getRoles()).thenReturn(List.of("AISP"));
            when(registrationRequest.getRedirectUris()).thenReturn(List.of(REDIRECT_URI));
            when(softwareStatement.getRedirectUris()).thenReturn(List.of(REDIRECT_URI));
            when(softwareStatement.getSoftwareStatementAssertion()).thenReturn(ssa);
            when(ssa.build()).thenReturn(SSA_AS_JWT_STR);
            // ... on next
            when(registrationRequest.toJsonValue())
                    .thenReturn(json(object(field(F_SCOPE, "accounts"),
                                            field(F_RESPONSE_TYPES, array()),
                                            field(F_TOKEN_ENDPOINT_AUTH_METHOD, "tls_client_auth"),
                                            field(F_REDIRECT_URIS, array(REDIRECT_URI.toString())))));
            Request request = new Request().setMethod("POST").setUri(REQUEST_URI);
            when(next.handle(attributesContext, request))
                    .thenReturn(newResponsePromise(new Response(OK).setEntity(json(object()))));
            // ... filter and context
            JsonValue config = validProcessRegistrationConfig();
            Filter filter = (Filter) new ScriptableFilter.Heaplet()
                    .create(Name.of("ProcessRegistration"), config, getHeap());
            attributesContext.getAttributes().put("registrationRequest", registrationRequest);
            attributesContext.getAttributes().put("clientCertificate", testTlsCert);
            // When
            final Response response = filter.filter(attributesContext, request, next).get();
            // Then
            assertThat(response.getStatus()).isEqualTo(OK);
            assertThat(response.getEntity().getJson())
                    .asInstanceOf(type(JsonValue.class))
                    .satisfies(jsonValue -> {
                        assertThat(jsonValue.get(F_SOFTWARE_STATEMENT).asString())
                                .isEqualTo(SSA_AS_JWT_STR);
                    });
            verify(next).handle(attributesContext, request);
            verify(registrationRequest).setMetadata("tls_client_certificate_bound_access_tokens", true);
            verify(registrationRequest).setResponseTypes(List.of(RESPONSE_TYPE));
        }

        @Test
        void shouldFailIfNoMatchingTlsCert() throws Exception {
            // Given
            // ... generate a different cert
            Pair<X509Certificate, JWKSet> pair = generateKeyCertAndJwks();
            X509Certificate nonMatchingCert = pair.getFirst();
            // ... registrationRequest content
            when(registrationRequest.getResponseTypes()).thenReturn(List.of(RESPONSE_TYPE));
            when(registrationRequest.getTokenEndpointAuthMethod()).thenReturn("tls_client_auth");
            when(registrationRequest.getMetadata(eq("tls_client_auth_subject_dn"))).thenReturn(new JsonValue(DN));
            when(registrationRequest.getMetadata("subject_type")).thenReturn(new JsonValue("pairwise"));
            when(registrationRequest.getSoftwareStatement()).thenReturn(softwareStatement);
            when(softwareStatement.getOrganisationId()).thenReturn("someorg");
            when(softwareStatement.getOrganisationName()).thenReturn("Some Org");
            when(softwareStatement.getJwkSetLocator()).thenReturn(Choice.withValue2(jwkSet));
            doAnswer(invocation -> null)
                    .when(registrationRequest).setMetadata("tls_client_certificate_bound_access_tokens", true);
            doAnswer(invocation -> null)
                    .when(registrationRequest).setMetadata(eq("jwks"), any());
            // ... registrationRequest validation
            when(registrationRequest.getScope()).thenReturn("accounts");
            when(softwareStatement.getRoles()).thenReturn(List.of("AISP"));
            when(registrationRequest.getRedirectUris()).thenReturn(List.of(REDIRECT_URI));
            when(softwareStatement.getRedirectUris()).thenReturn(List.of(REDIRECT_URI));
            when(softwareStatement.getSoftwareStatementAssertion()).thenReturn(ssa);
            when(ssa.build()).thenReturn(SSA_AS_JWT_STR);
            // ... filter and context (with non-matching cert)
            Request request = new Request().setMethod("POST").setUri(REQUEST_URI);
            JsonValue config = validProcessRegistrationConfig();
            Filter filter = (Filter) new ScriptableFilter.Heaplet()
                    .create(Name.of("ProcessRegistration"), config, getHeap());
            attributesContext.getAttributes().put("registrationRequest", registrationRequest);
            attributesContext.getAttributes().put("clientCertificate", nonMatchingCert);
            // When
            final Response response = filter.filter(attributesContext, request, next).get();
            // Then
            assertThat(response.getStatus()).isEqualTo(BAD_REQUEST);
            assertThat(response.getEntity().getJson())
                    .asInstanceOf(type(JsonValue.class))
                    .satisfies(jsonValue -> {
                        assertThat(jsonValue.get("error").asString()).isEqualTo(INVALID_SOFTWARE_STATEMENT_ERROR_CODE);
                        assertThat(jsonValue.get("error_description").asString())
                                .isEqualTo("tls transport cert does not match any certs "
                                                   + "registered in jwks for software statement");
                    });
            verifyNoInteractions(next);
        }
    }

    @Nested
    class TestPUT {
        @Test
        void shouldProcessValidRegistrationUpdate() throws Exception {
            // Given
            // ... registrationRequest content
            when(registrationRequest.getResponseTypes()).thenReturn(List.of(RESPONSE_TYPE));
            when(registrationRequest.getTokenEndpointAuthMethod()).thenReturn("tls_client_auth");
            when(registrationRequest.getMetadata(eq("tls_client_auth_subject_dn"))).thenReturn(new JsonValue(DN));
            when(registrationRequest.getMetadata("subject_type")).thenReturn(new JsonValue("pairwise"));
            when(registrationRequest.getSoftwareStatement()).thenReturn(softwareStatement);
            when(softwareStatement.getOrganisationId()).thenReturn("someorg");
            when(softwareStatement.getOrganisationName()).thenReturn("Some Org");
            when(softwareStatement.getJwkSetLocator()).thenReturn(Choice.withValue2(jwkSet));
            doAnswer(invocation -> null)
                    .when(registrationRequest).setMetadata("tls_client_certificate_bound_access_tokens", true);
            doAnswer(invocation -> null)
                    .when(registrationRequest).setMetadata(eq("jwks"), any());
            // ... registrationRequest validation
            when(registrationRequest.getScope()).thenReturn("accounts");
            when(softwareStatement.getRoles()).thenReturn(List.of("AISP"));
            when(registrationRequest.getRedirectUris()).thenReturn(List.of(REDIRECT_URI));
            when(softwareStatement.getRedirectUris()).thenReturn(List.of(REDIRECT_URI));
            when(softwareStatement.getSoftwareStatementAssertion()).thenReturn(ssa);
            when(ssa.build()).thenReturn(SSA_AS_JWT_STR);
            // ... on next
            when(registrationRequest.toJsonValue())
                    .thenReturn(json(object(field(F_SCOPE, "accounts"),
                                            field(F_RESPONSE_TYPES, array(RESPONSE_TYPE)),
                                            field(F_TOKEN_ENDPOINT_AUTH_METHOD, "tls_client_auth"),
                                            field(F_REDIRECT_URIS, array(REDIRECT_URI.toString())))));
            Request request = new Request().setMethod("PUT").setUri(REQUEST_URI);
            when(next.handle(attributesContext, request))
                    .thenReturn(newResponsePromise(new Response(OK).setEntity(json(object()))));
            // ... filter and context
            JsonValue config = validProcessRegistrationConfig();
            Filter filter = (Filter) new ScriptableFilter.Heaplet()
                    .create(Name.of("ProcessRegistration"), config, getHeap());
            attributesContext.getAttributes().put("registrationRequest", registrationRequest);
            attributesContext.getAttributes().put("clientCertificate", testTlsCert);
            // When
            final Response response = filter.filter(attributesContext, request, next).get();
            // Then - request apiClientId manipulated
            assertThat(request.getUri().toString()).isEqualTo("https://www.bank.com?client_id=" + API_CLIENT_ID);
            assertThat(response.getEntity().getJson())
                    .asInstanceOf(type(JsonValue.class))
                    .satisfies(jsonValue -> {
                        assertThat(jsonValue.get(F_SOFTWARE_STATEMENT).asString())
                                .isEqualTo(SSA_AS_JWT_STR);
                    });
            verify(next).handle(attributesContext, request);
            verify(registrationRequest).setMetadata("tls_client_certificate_bound_access_tokens", true);
            verify(registrationRequest).setMetadata(eq("jwks"), any());  // can't verify eq(jwkSet)
        }
    }

    @Nested
    class TestGET {
        @Test
        void shouldProcessValidRegistrationQuery() throws Exception {
            // Given
            when(ssa.build()).thenReturn(SSA_AS_JWT_STR);
            Request request = new Request().setMethod("GET").setUri(REQUEST_URI);
            when(next.handle(attributesContext, request))
                    .thenReturn(newResponsePromise(new Response(OK).setEntity(json(object()))));
            // ... filter and context
            JsonValue config = validProcessRegistrationConfig();
            Filter filter = (Filter) new ScriptableFilter.Heaplet()
                    .create(Name.of("ProcessRegistration"), config, getHeap());
            attributesContext.getAttributes().put("apiClient", apiClient(ssa));
            // When
            final Response response = filter.filter(attributesContext, request, next).get();
            // Then - request apiClientId manipulated
            assertThat(request.getUri().toString()).isEqualTo("https://www.bank.com?client_id=" + API_CLIENT_ID);
            assertThat(response.getEntity().getJson())
                    .asInstanceOf(type(JsonValue.class))
                    .satisfies(jsonValue -> {
                        assertThat(jsonValue.get(F_SOFTWARE_STATEMENT).asString())
                                .isEqualTo(SSA_AS_JWT_STR);
                    });
            verify(next).handle(attributesContext, request);
        }

        private static ApiClient apiClient(final SignedJwt ssa) {
            return ApiClient.builder()
                            .oAuth2ClientId(API_CLIENT_ID)
                            .clientName("Fintech1")
                            .softwareId("fintech1")
                            .organisation(new ApiClientOrganisation("fintech", "FinTech"))
                            .roles(List.of("accounts"))
                            .withEmbeddedJwksSupplier(jwkSet)
                            .softwareStatementAssertion(ssa)
                            .build();
        }
    }

    private static Pair<X509Certificate, JWKSet> generateKeyCertAndJwks() throws JOSEException {
        KeyPair keyPair = generateRsaKeyPair();
        X509Certificate cert = generateX509Cert(keyPair, DN);
        JWK jwk = createJwkForCert(cert, new KeyUse("tls"));
        JWKSet jwkSet = JWKSet.parse(new com.nimbusds.jose.jwk.JWKSet(List.of(jwk)).toString());
        return Pair.of(cert, jwkSet);
    }

    private static JsonValue validProcessRegistrationConfig() {
        return json(object(field("type", GROOVY_MIME_TYPE),
                           field("file", "ProcessRegistration.groovy"),
                           field("args",
                                 object(field("jwkSetService", "${heap['JwkSetService']}"),
                                        field("allowIgIssuedTestCerts", true),
                                        field("jwtSignatureValidator", null),
                                        field("tokenEndpointAuthMethodsSupported", array("tls_client_auth")),
                                        field("trustedDirectoryService", "${heap['TrustedDirectoryService']}")))));
    }

    private static JsonValue validProcessRegistrationConfigPreventIgTestCerts() {
        return json(object(field("type", GROOVY_MIME_TYPE),
                           field("file", "ProcessRegistration.groovy"),
                           field("args",
                                 object(field("jwkSetService", "${heap['JwkSetService']}"),
                                        field("allowIgIssuedTestCerts", false),
                                        field("jwtSignatureValidator", null),
                                        field("tokenEndpointAuthMethodsSupported", array("tls_client_auth")),
                                        field("trustedDirectoryService", "${heap['TrustedDirectoryService']}")))));
    }
}
