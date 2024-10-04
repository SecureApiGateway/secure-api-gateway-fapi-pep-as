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
package com.forgerock.sapi.gateway.fapi.v1.authorize;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

import org.forgerock.http.header.ContentTypeHeader;
import org.forgerock.http.protocol.Request;
import org.forgerock.http.protocol.Response;
import org.forgerock.http.protocol.Status;
import org.forgerock.json.JsonValue;
import org.forgerock.services.context.Context;
import org.forgerock.services.context.RootContext;
import org.forgerock.util.promise.NeverThrowsException;
import org.forgerock.util.promise.Promise;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import com.forgerock.sapi.gateway.common.rest.HttpMediaTypes;
import com.forgerock.sapi.gateway.util.CryptoUtils;
import com.forgerock.sapi.gateway.util.TestHandlers.TestSuccessResponseHandler;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader.Builder;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

public abstract class BaseFapiAuthorizeRequestValidationFilterTest {

    protected final BaseFapiAuthorizeRequestValidationFilter filter;
    protected final Context context = new RootContext("test");
    private final JWTSigner jwtSigner = new JWTSigner();
    protected TestSuccessResponseHandler successResponseHandler;

    public BaseFapiAuthorizeRequestValidationFilterTest(BaseFapiAuthorizeRequestValidationFilter filter) {
        this.filter = filter;
    }

    private static Response getResponse(Promise<Response, NeverThrowsException> responsePromise) {
        try {
            return responsePromise.getOrThrow(1, TimeUnit.SECONDS);
        } catch (InterruptedException | TimeoutException e) {
            throw new RuntimeException("Failed to get response from promise", e);
        }
    }

    @BeforeEach
    void beforeEach() {
        successResponseHandler = new TestSuccessResponseHandler();
    }

    @Test
    void failsWhenInvalidHttpMethodIsUsed() throws Exception {
        final Request request = new Request();
        request.setUri("http://localhost/authorize");
        request.setMethod("PUT");

        final Promise<Response, NeverThrowsException> responsePromise = filter.filter(context, request, successResponseHandler);

        final Response response = BaseFapiAuthorizeRequestValidationFilterTest.getResponse(responsePromise);
        assertEquals(Status.METHOD_NOT_ALLOWED, response.getStatus());
        assertFalse(successResponseHandler.hasBeenInteractedWith()); // Never got to the handler
    }

    @Test
    void failsWhenRequestParamIsMissing() throws Exception {
        final Request request = new Request();
        request.setUri("https://localhost/am/authorize");
        request.setMethod("GET");

        final Promise<Response, NeverThrowsException> responsePromise = filter.filter(context, request, successResponseHandler);

        validateErrorResponse(responsePromise, "Request must have a 'request' parameter the value of which must be a signed jwt");
    }

    @Test
    void failsWhenRequestParamIsSpecifiedMultipleTimes() throws Exception {
        final Request request = new Request();
        request.setUri("https://localhost/am/authorize?request=req1&request=req2");
        request.setMethod("GET");

        final Promise<Response, NeverThrowsException> responsePromise = filter.filter(context, request, successResponseHandler);

        validateErrorResponse(responsePromise, "Request must have a 'request' parameter the value of which must be a signed jwt");
    }

    @Test
    void failsWhenRequestParamIsNotValidJWT() throws Exception {
        final Request requestWithInvalidJwt = createRequest("invalid-jwt", "state");

        final Promise<Response, NeverThrowsException> responsePromise = filter.filter(context, requestWithInvalidJwt, successResponseHandler);

        validateErrorResponse(responsePromise, "Request must have a 'request' parameter the value of which must be a signed jwt");
    }

    @Test
    void failsWhenRequestJwtIsMissingRedirectUriClaim() throws Exception {
        final String state = UUID.randomUUID().toString();
        final JWTClaimsSet requestClaims = JWTClaimsSet.parse(Map.of("client_id", "client-123",
                "nonce", "sdffdsdfdssfd",
                "state", state,
                "scope", "payments",
                "response_type", "jwt"));
        final String signedRequestJwt = jwtSigner.createSignedRequestJwt(requestClaims);

        final Request request = createRequest(signedRequestJwt, state);
        final Promise<Response, NeverThrowsException> responsePromise = filter.filter(context, request, successResponseHandler);

        validateErrorResponse(responsePromise, "Request JWT must have a 'redirect_uri' claim");
    }

    @Test
    void failsWhenRequestJwtIsMissingClientIdClaim() throws Exception {
        final String state = UUID.randomUUID().toString();
        final JWTClaimsSet requestClaims = JWTClaimsSet.parse(Map.of("redirect_uri", "https://test-tpp.com/redirect",
                "nonce", "sdffdsdfdssfd",
                "state", state,
                "scope", "payments",
                "response_type", "jwt"));
        final String signedRequestJwt = jwtSigner.createSignedRequestJwt(requestClaims);

        final Request request = createRequest(signedRequestJwt, state);
        final Promise<Response, NeverThrowsException> responsePromise = filter.filter(context, request, successResponseHandler);

        validateErrorResponse(responsePromise, "Request JWT must have a 'client_id' claim");
    }

    @Test
    void failsWhenRequestJwtIsMissingScopeClaim() throws Exception {
        final String state = UUID.randomUUID().toString();
        final JWTClaimsSet requestClaims = JWTClaimsSet.parse(Map.of("redirect_uri", "https://test-tpp.com/redirect",
                "nonce", "sdffdsdfdssfd",
                "state", state,
                "client_id", "client-123",
                "response_type", "jwt"));
        final String signedRequestJwt = jwtSigner.createSignedRequestJwt(requestClaims);

        final Request request = createRequest(signedRequestJwt, state);
        final Promise<Response, NeverThrowsException> responsePromise = filter.filter(context, request, successResponseHandler);

        validateErrorResponse(responsePromise, "Request JWT must have a 'scope' claim");
    }

    @Test
    void failsWhenRequestJwtIsMissingNonceClaim() throws Exception {
        final String state = UUID.randomUUID().toString();
        final JWTClaimsSet requestClaims = JWTClaimsSet.parse(Map.of("redirect_uri", "https://test-tpp.com/redirect",
                "scope", "sdffdsdfdssfd",
                "state", state,
                "client_id", "client-123",
                "response_type", "jwt"));
        final String signedRequestJwt = jwtSigner.createSignedRequestJwt(requestClaims);

        final Request request = createRequest(signedRequestJwt, state);
        final Promise<Response, NeverThrowsException> responsePromise = filter.filter(context, request, successResponseHandler);

        validateErrorResponse(responsePromise, "Request JWT must have a 'nonce' claim");
    }

    @Test
    void failsWhenRequestJwtIsMissingResponseTypeClaim() throws Exception {
        final String state = UUID.randomUUID().toString();
        final JWTClaimsSet requestClaims = JWTClaimsSet.parse(Map.of("redirect_uri", "https://test-tpp.com/redirect",
                "scope", "sdffdsdfdssfd",
                "nonce", "adsaddas",
                "state", state,
                "client_id", "client-123"));
        final String signedRequestJwt = jwtSigner.createSignedRequestJwt(requestClaims);

        final Request request = createRequest(signedRequestJwt, state);
        final Promise<Response, NeverThrowsException> responsePromise = filter.filter(context, request, successResponseHandler);

        validateErrorResponse(responsePromise, "Request JWT must have a 'response_type' claim");
    }

    @Test
    void failsWithTextResponseWhenAcceptHeaderIsConfigured() throws Exception {
        final String state = UUID.randomUUID().toString();
        final JWTClaimsSet requestClaims = JWTClaimsSet.parse(Map.of("redirect_uri", "https://test-tpp.com/redirect",
                "scope", "sdffdsdfdssfd",
                "nonce", "adsaddas",
                "state", state,
                "client_id", "client-123"));
        final String signedRequestJwt = jwtSigner.createSignedRequestJwt(requestClaims);

        final Request request = createRequest(signedRequestJwt, state);
        request.getHeaders().add("Accept", HttpMediaTypes.APPLICATION_TEXT);
        final Promise<Response, NeverThrowsException> responsePromise = filter.filter(context, request, successResponseHandler);

        final Response response = BaseFapiAuthorizeRequestValidationFilterTest.getResponse(responsePromise);
        assertEquals(Status.BAD_REQUEST, response.getStatus());
        assertEquals(HttpMediaTypes.APPLICATION_TEXT, response.getHeaders().get(ContentTypeHeader.class).getType());
        assertEquals("error: invalid_request\n" +
                "error_description: Request JWT must have a 'response_type' claim\n", response.getEntity().getString());
    }

    @Test
    void succeedsForValidRequest() throws Exception {
        final String state = UUID.randomUUID().toString();
        final JWTClaimsSet requestClaims = JWTClaimsSet.parse(Map.of("client_id", "client-123",
                "redirect_uri", "https://test-tpp.com/redirect",
                "nonce", "sdffdsdfdssfd",
                "state", state,
                "scope", "openid payments",
                "response_type", "code id_token"));
        final String signedRequestJwt = jwtSigner.createSignedRequestJwt(requestClaims);

        final Request request = createRequest(signedRequestJwt, state);

        final Promise<Response, NeverThrowsException> responsePromise = filter.filter(context, request, successResponseHandler);
        validateSuccessResponse(responsePromise);
    }

    @Test
    void succeedsForValidRequestWithoutStateClaim() throws Exception {
        final JWTClaimsSet requestClaims = JWTClaimsSet.parse(Map.of("client_id", "client-123",
                "redirect_uri", "https://test-tpp.com/redirect",
                "nonce", "sdffdsdfdssfd",
                "scope", "openid payments",
                "response_type", "code id_token"));
        final String signedRequestJwt = jwtSigner.createSignedRequestJwt(requestClaims);

        // state param in URI but NOT in jwt claims
        final Request request = createRequest(signedRequestJwt, "state-12334");
        final Promise<Response, NeverThrowsException> responsePromise = filter.filter(context, request, successResponseHandler);

        validateSuccessResponse(responsePromise);
        // Verify that state param was removed from the request that was sent onwards
        validateHandlerReceivedRequestWithoutStateParam();
    }

    @ParameterizedTest
    @ValueSource(strings = {"jwt", "query.jwt", "fragment.jwt", "form_post.jwt"})
    void succeedsForValidRequestUsingJarm(String jwtResponseMode) throws Exception {
        final String state = UUID.randomUUID().toString();
        final JWTClaimsSet requestClaims = JWTClaimsSet.parse(Map.of("client_id", "client-123",
                "redirect_uri", "https://test-tpp.com/redirect",
                "nonce", "sdffdsdfdssfd",
                "state", state,
                "scope", "openid payments",
                "response_type", "code",
                "response_mode", jwtResponseMode));
        final String signedRequestJwt = jwtSigner.createSignedRequestJwt(requestClaims);

        final Request request = createRequest(signedRequestJwt, state);

        final Promise<Response, NeverThrowsException> responsePromise = filter.filter(context, request, successResponseHandler);
        validateSuccessResponse(responsePromise);
    }

    @Test
    void failsWhenResponseTypesCodeMissingResponseMode() throws Exception {
        final String state = UUID.randomUUID().toString();
        final JWTClaimsSet requestClaims = JWTClaimsSet.parse(Map.of("client_id", "client-123",
                "redirect_uri", "https://test-tpp.com/redirect",
                "nonce", "sdffdsdfdssfd",
                "state", state,
                "scope", "openid payments",
                "response_type", "code"));
        final String signedRequestJwt = jwtSigner.createSignedRequestJwt(requestClaims);

        final Request request = createRequest(signedRequestJwt, state);
        final Promise<Response, NeverThrowsException> responsePromise = filter.filter(context, request, successResponseHandler);

        validateErrorResponse(responsePromise, "response_mode must be specified when response_type is: \"code\"");
    }

    @Test
    void failsWhenResponseTypeCodeInvalidResponseMode() throws Exception {
        final String state = UUID.randomUUID().toString();
        final JWTClaimsSet requestClaims = JWTClaimsSet.parse(Map.of("client_id", "client-123",
                "redirect_uri", "https://test-tpp.com/redirect",
                "nonce", "sdffdsdfdssfd",
                "state", state,
                "scope", "openid payments",
                "response_type", "code",
                "response_mode", "not-supported"));
        final String signedRequestJwt = jwtSigner.createSignedRequestJwt(requestClaims);

        final Request request = createRequest(signedRequestJwt, state);
        final Promise<Response, NeverThrowsException> responsePromise = filter.filter(context, request, successResponseHandler);

        validateErrorResponse(responsePromise, "response_mode must be: \"jwt\" when response_type is: \"code\"");
    }

    @Test
    void failsWhenResponseTypeCodeIdDoesNotHaveOpenIdScope() throws Exception {
        final String state = UUID.randomUUID().toString();
        final JWTClaimsSet requestClaims = JWTClaimsSet.parse(Map.of("client_id", "client-123",
                "redirect_uri", "https://test-tpp.com/redirect",
                "nonce", "sdffdsdfdssfd",
                "state", state,
                "scope", "payments",
                "response_type", "code id_token"));
        final String signedRequestJwt = jwtSigner.createSignedRequestJwt(requestClaims);

        final Request request = createRequest(signedRequestJwt, state);
        final Promise<Response, NeverThrowsException> responsePromise = filter.filter(context, request, successResponseHandler);

        validateErrorResponse(responsePromise, "request object must include openid as one of the requested scopes when response_type is: \"code id_token\"");
    }

    @Test
    void failsWhenResponseTypeIsInvalid() throws Exception {
        final String state = UUID.randomUUID().toString();
        final JWTClaimsSet requestClaims = JWTClaimsSet.parse(Map.of("client_id", "client-123",
                "redirect_uri", "https://test-tpp.com/redirect",
                "nonce", "sdffdsdfdssfd",
                "state", state,
                "scope", "payments",
                "response_type", "id_token"));
        final String signedRequestJwt = jwtSigner.createSignedRequestJwt(requestClaims);

        final Request request = createRequest(signedRequestJwt, state);
        final Promise<Response, NeverThrowsException> responsePromise = filter.filter(context, request, successResponseHandler);

        validateErrorResponse(responsePromise, "response_type not supported, must be one of: \"code\", \"code id_token\"");
    }

    protected abstract Request createRequest(String requestJwt, String state) throws Exception;

    private void validateErrorResponse(Promise<Response, NeverThrowsException> responsePromise, String expectedErrorMessage) throws IOException {
        final Response response = BaseFapiAuthorizeRequestValidationFilterTest.getResponse(responsePromise);
        assertEquals(Status.BAD_REQUEST, response.getStatus());

        final JsonValue json = JsonValue.json(response.getEntity().getJson());
        assertEquals("invalid_request", json.get("error").asString());
        assertEquals(expectedErrorMessage, json.get("error_description").asString());
        assertFalse(successResponseHandler.hasBeenInteractedWith()); // Never got to the handler
    }

    protected void validateSuccessResponse(Promise<Response, NeverThrowsException> responsePromise) {
        final Response response = BaseFapiAuthorizeRequestValidationFilterTest.getResponse(responsePromise);
        validateSuccessResponse(response);
    }

    private void validateSuccessResponse(Response response) {
        assertEquals(Status.OK, response.getStatus());
        assertTrue(successResponseHandler.hasBeenInteractedWith());
    }

    private void validateHandlerReceivedRequestWithStateParam(String expectedState) {
        final Request processedRequest = successResponseHandler.getProcessedRequests().get(0);
        assertEquals(expectedState, getRequestState(processedRequest));
    }

    protected abstract String getRequestState(Request request);

    protected void validateHandlerReceivedRequestWithoutStateParam() {
        final Request processedRequest = successResponseHandler.getProcessedRequests().get(0);
        assertNull(getRequestState(processedRequest));
    }
}
