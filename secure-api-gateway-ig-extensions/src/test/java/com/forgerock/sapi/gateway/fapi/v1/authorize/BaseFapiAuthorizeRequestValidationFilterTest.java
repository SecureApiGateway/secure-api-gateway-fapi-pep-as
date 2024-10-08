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

import static com.forgerock.sapi.gateway.common.jwt.AuthorizeRequestParameterNames.CLIENT_ID;
import static com.forgerock.sapi.gateway.common.jwt.AuthorizeRequestParameterNames.NONCE;
import static com.forgerock.sapi.gateway.common.jwt.AuthorizeRequestParameterNames.REDIRECT_URI;
import static com.forgerock.sapi.gateway.common.jwt.AuthorizeRequestParameterNames.RESPONSE_MODE;
import static com.forgerock.sapi.gateway.common.jwt.AuthorizeRequestParameterNames.RESPONSE_TYPE;
import static com.forgerock.sapi.gateway.common.jwt.AuthorizeRequestParameterNames.SCOPE;
import static com.forgerock.sapi.gateway.common.jwt.AuthorizeRequestParameterNames.STATE;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.util.HashMap;
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
import com.forgerock.sapi.gateway.util.TestHandlers.TestSuccessResponseHandler;
import com.nimbusds.jwt.JWTClaimsSet;

public abstract class BaseFapiAuthorizeRequestValidationFilterTest {

    protected final BaseFapiAuthorizeRequestValidationFilter filter;
    protected final Context context = new RootContext("test");

    protected final String VALID_SCOPE_CLAIMS = "openid payments";
    protected final String VALID_NONCE_CLAIM = "lkfhfgufdjlkdsfj";
    protected final String VALID_RESPONSE_TYPE_CLAIM = "code id_token";
    protected final String VALID_REDIRECT_URI_CLAIM = "https://test-tpp.com/redirect";
    protected final String VALID_CLIENT_ID_CLAIM = "client-123";
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
        final Map<String, Object> claimsMap = getEndpointSpecificMapOfClaims();
        claimsMap.remove(REDIRECT_URI);
        final JWTClaimsSet requestClaims = JWTClaimsSet.parse(claimsMap);

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
        final JWTClaimsSet requestClaims = JWTClaimsSet.parse(getEndpointSpecificMapOfClaims());
        final String signedRequestJwt = jwtSigner.createSignedRequestJwt(requestClaims);

        final Request request = createRequest(signedRequestJwt, state);

        final Promise<Response, NeverThrowsException> responsePromise = filter.filter(context, request, successResponseHandler);
        validateSuccessResponse(responsePromise);
    }

    @Test
    void succeedsForValidRequestWithoutStateClaim() throws Exception {
        HashMap<String, Object> jarClaims = getEndpointSpecificMapOfClaims();
        jarClaims.remove(STATE);
        final JWTClaimsSet requestClaims = JWTClaimsSet.parse(jarClaims);
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
        HashMap<String, Object> jarClaims = getEndpointSpecificMapOfClaims();
        jarClaims.put(RESPONSE_TYPE, "code");
        jarClaims.put(RESPONSE_MODE, jwtResponseMode);
        final JWTClaimsSet requestClaims = JWTClaimsSet.parse(jarClaims);
        final String signedRequestJwt = jwtSigner.createSignedRequestJwt(requestClaims);

        final Request request = createRequest(signedRequestJwt, state);

        final Promise<Response, NeverThrowsException> responsePromise = filter.filter(context, request, successResponseHandler);
        validateSuccessResponse(responsePromise);
    }

    @Test
    void failsWhenResponseTypesCodeMissingResponseMode() throws Exception {
        final String state = UUID.randomUUID().toString();
        HashMap<String, Object> jarClaims = getEndpointSpecificMapOfClaims();
        jarClaims.put(RESPONSE_TYPE, "code");
        jarClaims.remove(RESPONSE_MODE);

        final JWTClaimsSet requestClaims = JWTClaimsSet.parse(jarClaims);
        final String signedRequestJwt = jwtSigner.createSignedRequestJwt(requestClaims);

        final Request request = createRequest(signedRequestJwt, state);
        final Promise<Response, NeverThrowsException> responsePromise = filter.filter(context, request, successResponseHandler);

        validateErrorResponse(responsePromise, "response_mode must be specified when response_type is: \"code\"");
    }

    @Test
    void failsWhenResponseTypeCodeInvalidResponseMode() throws Exception {
        final String state = UUID.randomUUID().toString();
        Map<String, Object> validClaims = getEndpointSpecificMapOfClaims();
        validClaims.put(RESPONSE_TYPE, "code");
        validClaims.put(RESPONSE_MODE, "not-supported");
        final JWTClaimsSet requestClaims = JWTClaimsSet.parse(validClaims);

        final String signedRequestJwt = jwtSigner.createSignedRequestJwt(requestClaims);

        final Request request = createRequest(signedRequestJwt, state);
        final Promise<Response, NeverThrowsException> responsePromise = filter.filter(context, request, successResponseHandler);

        validateErrorResponse(responsePromise, "response_mode must be: \"jwt\" when response_type is: \"code\"");
    }

    @Test
    void failsWhenResponseTypeCodeIdDoesNotHaveOpenIdScope() throws Exception {
        final String state = UUID.randomUUID().toString();
        HashMap<String, Object> jarClaims = getEndpointSpecificMapOfClaims();
        jarClaims.put(SCOPE, "payments");
        final JWTClaimsSet requestClaims = JWTClaimsSet.parse(jarClaims);
        final String signedRequestJwt = jwtSigner.createSignedRequestJwt(requestClaims);

        final Request request = createRequest(signedRequestJwt, state);
        final Promise<Response, NeverThrowsException> responsePromise = filter.filter(context, request, successResponseHandler);

        validateErrorResponse(responsePromise, "request object must include openid as one of the requested scopes when response_type is: \"code id_token\"");
    }

    @Test
    void failsWhenResponseTypeIsInvalid() throws Exception {
        final String state = UUID.randomUUID().toString();
        HashMap<String, Object> jarClaims = getEndpointSpecificMapOfClaims();
        jarClaims.put(RESPONSE_TYPE, "id_token");
        final JWTClaimsSet requestClaims = JWTClaimsSet.parse(jarClaims);
        final String signedRequestJwt = jwtSigner.createSignedRequestJwt(requestClaims);

        final Request request = createRequest(signedRequestJwt, state);
        final Promise<Response, NeverThrowsException> responsePromise = filter.filter(context, request, successResponseHandler);

        validateErrorResponse(responsePromise, "response_type not supported, must be one of: \"code\", \"code id_token\"");
    }

    protected abstract Request createRequest(String requestJwt, String state) throws Exception;

    void validateErrorResponse(Promise<Response, NeverThrowsException> responsePromise, String expectedErrorMessage) throws IOException {
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

    protected abstract String getRequestState(Request request);

    /**
     * Get the default required JAR claims for the JAR request. The required claims will be different for the par and
     * the authorize endpoint.
     * @return {@code Map<String, String>} containing the default claims for the PAR or authorize request
     */
    protected abstract HashMap<String, Object> getEndpointSpecificMapOfClaims();

    /**
     * Get a valid set of claims common to both par and authorize endpoints
     * @return {@code Map<String, String>} containing a valid set of claims common to the par and authorize endpoints
     */
    protected HashMap<String, Object> getCommonMapOfClaims(){
        HashMap<String, Object> validMapOfClaims = new HashMap<>(Map.of(
                SCOPE, VALID_SCOPE_CLAIMS,
                NONCE, VALID_NONCE_CLAIM,
                RESPONSE_TYPE, VALID_RESPONSE_TYPE_CLAIM,
                REDIRECT_URI, VALID_REDIRECT_URI_CLAIM,
                CLIENT_ID, VALID_CLIENT_ID_CLAIM
        ));
        return validMapOfClaims;
    }

    protected void validateHandlerReceivedRequestWithoutStateParam() {
        final Request processedRequest = successResponseHandler.getProcessedRequests().get(0);
        assertNull(getRequestState(processedRequest));
    }
}
