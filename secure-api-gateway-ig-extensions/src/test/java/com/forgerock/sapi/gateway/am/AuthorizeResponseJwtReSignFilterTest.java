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
package com.forgerock.sapi.gateway.am;

import static com.forgerock.sapi.gateway.util.TestHandlers.invokeFilter;
import static org.forgerock.json.JsonValue.field;
import static org.forgerock.json.JsonValue.json;
import static org.forgerock.json.JsonValue.object;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.net.URISyntaxException;
import java.security.KeyPair;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

import org.forgerock.http.MutableUri;
import org.forgerock.http.header.LocationHeader;
import org.forgerock.http.protocol.Form;
import org.forgerock.http.protocol.Header;
import org.forgerock.http.protocol.Request;
import org.forgerock.http.protocol.Response;
import org.forgerock.http.protocol.Status;
import org.forgerock.json.jose.common.JwtReconstruction;
import org.forgerock.json.jose.jws.SignedJwt;
import org.forgerock.openig.heap.HeapException;
import org.forgerock.openig.heap.HeapImpl;
import org.forgerock.openig.heap.Name;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import com.forgerock.sapi.gateway.am.AuthorizeResponseJwtReSignFilter.Heaplet;
import com.forgerock.sapi.gateway.util.CryptoUtils;
import com.forgerock.sapi.gateway.util.TestHandlers.FixedResponseHandler;
import com.forgerock.sapi.gateway.util.TestHandlers.TestHandler;
import com.nimbusds.jose.crypto.RSASSASigner;

class AuthorizeResponseJwtReSignFilterTest {

    private static final String REDIRECT_URI = "https://acme-fintech/callback";
    private static final String ID_TOKEN = "id_token";
    private static final String AUTHORISATION_CODE_PARAM = "code";
    private static final String AUTHORISATION_CODE_VALUE = "fsfgfgftwtqrtwq34";
    private static final String RESPONSE_PARAM = "response";

    private final JwtReSignerTestResourceManager jwtReSignerTestResourceManager;
    private final JwtReSigner jwtReSigner;
    private final RSASSASigner tppJwtSigner;
    private final String tppKeyId = "tpp-kid";

    public AuthorizeResponseJwtReSignFilterTest() {
        jwtReSignerTestResourceManager = new JwtReSignerTestResourceManager();
        jwtReSigner = jwtReSignerTestResourceManager.getJwtReSigner();

        final KeyPair tppKeyPair = CryptoUtils.generateRsaKeyPair();
        this.tppJwtSigner = new RSASSASigner(tppKeyPair.getPrivate());
    }

    AuthorizeResponseJwtReSignFilter createFilter() {
        final Heaplet heaplet = new Heaplet();
        final HeapImpl heap = new HeapImpl(Name.of("heap"));
        heap.put("jwtReSigner", jwtReSigner);
        try {
            return (AuthorizeResponseJwtReSignFilter) heaplet.create(Name.of("test"), json(object(field("jwtReSigner", "jwtReSigner"))), heap);
        } catch (HeapException e) {
            throw new RuntimeException(e);
        }
    }

    private static Response buildAuthoriseEndpointFragmentResponse(String idToken) {
        return buildAuthoriseEndpointResponse(true, buildPlainResponseModeFormParams(idToken));
    }

    private static Response buildAuthoriseEndpointQueryResponse(String idToken) {
        return buildAuthoriseEndpointResponse(false, buildPlainResponseModeFormParams(idToken));
    }

    private static Form buildPlainResponseModeFormParams(String idToken) {
        final Form form = new Form();
        form.add(AUTHORISATION_CODE_PARAM, AUTHORISATION_CODE_VALUE);
        form.add(ID_TOKEN, idToken);
        return form;
    }

    private static Response buildAuthoriseEndpointResponse(boolean fragment, Form formParams) {
        final MutableUri locationUri;
        try {
            locationUri = new MutableUri(REDIRECT_URI);
            if (fragment) {
                locationUri.setFragment(formParams.toQueryString());
            } else {
                locationUri.setQuery(formParams.toQueryString());
            }
        } catch (URISyntaxException e) {
            throw new RuntimeException(e);
        }
        return new Response(Status.FOUND).addHeaders(new LocationHeader(locationUri.toString()));
    }

    private static Request createAuthorizeRequest() {
        final Request request = new Request();
        try {
            request.setUri("http://iam.forgerock.financial/authorize");
            return request;
        } catch (URISyntaxException e) {
            throw new RuntimeException(e);
        }
    }

    private Request createAuthorizeRequestJwtResponseMode() {
        return createAuthorizeRequestJwtResponseMode("jwt");
    }

    private Request createAuthorizeRequestJwtResponseMode(String jwtResponseMode) {
        final Request authorizeRequest = createAuthorizeRequest();
        try {
            // Create the request JWT and sign it as the TPP
            final Map<String, Object> requestJwtClaims = Map.of("response_mode", jwtResponseMode);
            final String requestJwtStr = jwtReSignerTestResourceManager.createSignedJwt(tppJwtSigner, tppKeyId, UUID.randomUUID().toString(), requestJwtClaims);
            authorizeRequest.getUri().setQuery("request=" + requestJwtStr);
        } catch (URISyntaxException e) {
            throw new RuntimeException(e);
        }
        return authorizeRequest;
    }

    @Test
    void testAmErrorResponsesArePassedThrough()  {
        final TestHandler responseHandler = new FixedResponseHandler(new Response(Status.BAD_REQUEST));

        final Response response = invokeFilter(createFilter(), createAuthorizeRequest(), responseHandler);
        assertEquals(Status.BAD_REQUEST, response.getStatus());
    }

    @Test
    void testAmResponseWithoutLocationHeaderIsPassedThrough() {
        // 200 response returned rather than redirect
        final TestHandler responseHandler = new FixedResponseHandler(new Response(Status.OK));

        final Response response = invokeFilter(createFilter(), createAuthorizeRequest(), responseHandler);
        assertEquals(Status.OK, response.getStatus());
    }

    @ParameterizedTest
    @ValueSource(strings = {"jwt", "query.jwt", "fragment.jwt", "form_post.jwt"})
    void testIsJwtResponseModeHandlesAllJwtResponseModeValues(String jwtResponseMode) {
        assertTrue(createFilter().isJwtResponseMode(createAuthorizeRequestJwtResponseMode(jwtResponseMode)));
    }

    @ParameterizedTest
    @ValueSource(strings = {"query", "fragment", "form_post"})
    void testIsJwtResponseModeReturnsFalseForNonJwtModes(String jwtResponseMode) {
        assertFalse(createFilter().isJwtResponseMode(createAuthorizeRequestJwtResponseMode(jwtResponseMode)));
    }

    @Test
    void testIsJwtResponseModeReturnsFalseWhenRequestParamIsMissing() throws Exception {
        assertFalse(createFilter().isJwtResponseMode(new Request().setUri("https://localhost/authorize?response_type=code")));
    }

    @Nested
    class PlainResponseModeTests {
        @Test
        void testAuthoriseEndpointFragmentIdTokenIsReSigned() {
            testAuthoriseEndpointFragmentIdTokenIsReSigned(createFilter());
        }

        private void testAuthoriseEndpointFragmentIdTokenIsReSigned(AuthorizeResponseJwtReSignFilter filter) {
            final String expectedJti = UUID.randomUUID().toString();
            final TestHandler responseHandler = new FixedResponseHandler(buildAuthoriseEndpointFragmentResponse(jwtReSignerTestResourceManager.createAmSignedIdToken(expectedJti)));
            final Request request = createAuthorizeRequest();

            final Response response = invokeFilter(filter, request, responseHandler);

            validateSuccessAuthoriseFragmentResponse(response, expectedJti);
        }

        @Test
        void testAuthoriseEndpointQueryIdTokenIsReSigned() {
            testAuthoriseEndpointQueryIdTokenIsReSigned(createFilter());
        }

        private void testAuthoriseEndpointQueryIdTokenIsReSigned(AuthorizeResponseJwtReSignFilter filter) {
            final String expectedJti = UUID.randomUUID().toString();
            final TestHandler responseHandler = new FixedResponseHandler(buildAuthoriseEndpointQueryResponse(jwtReSignerTestResourceManager.createAmSignedIdToken(expectedJti)));

            final Response response = invokeFilter(filter, createAuthorizeRequest(), responseHandler);

            validateSuccessAuthoriseQueryResponse(response, expectedJti);
        }

        @Test
        void testReSignerFailuresCauseInternalServerError() {
            final String expectedJti = UUID.randomUUID().toString();
            // Return an id_token that has not been signed by AM and will therefore fail sig validation in the re-signer
            final String idTokenNotSignedByAm = jwtReSignerTestResourceManager.createSignedIdToken(tppJwtSigner, tppKeyId, expectedJti);
            final TestHandler responseHandler = new FixedResponseHandler(buildAuthoriseEndpointQueryResponse(idTokenNotSignedByAm));

            final Response response = invokeFilter(createFilter(), createAuthorizeRequest(), responseHandler);

            assertEquals(Status.INTERNAL_SERVER_ERROR, response.getStatus());
        }

        @Test
        void testAmResponseWithoutIdTokenIsPassedThrough() {
            // plain response_mode i.e. not JARM, without an id_token is passed through
            final String locationUri = REDIRECT_URI +  "?" + AUTHORISATION_CODE_PARAM + "=" + AUTHORISATION_CODE_VALUE;

            final Response amResponse = new Response(Status.FOUND);
            amResponse.addHeaders(new LocationHeader(locationUri));

            final TestHandler responseHandler = new FixedResponseHandler(amResponse);

            final Response response = invokeFilter(createFilter(), createAuthorizeRequest(), responseHandler);
            assertEquals(Status.FOUND, response.getStatus());
            assertEquals(locationUri, getLocationUri(response).toString());
        }
    }

    @Nested
    class JwtResponseModeTests {

        @Test
        void responseJwtIsReSigned() {
            testResponseJwtIsReSignedAuthorizeResponseJwtReSigned(createFilter());
        }

        private void testResponseJwtIsReSignedAuthorizeResponseJwtReSigned(AuthorizeResponseJwtReSignFilter filter) {
            final String responseJwtJti = UUID.randomUUID().toString();
            final TestHandler responseHandler = new FixedResponseHandler(buildJwtResponse(responseJwtJti, null));
            final Request request = createAuthorizeRequestJwtResponseMode();

            final Response response = invokeFilter(filter, request, responseHandler);

            validateSuccessJwtResponseModeResponse(response, responseJwtJti, null);
        }


        void validateSuccessJwtResponseModeResponse(Response response, String expectedResponseJwtJti, String expectedIdTokenJti) {
            assertEquals(Status.FOUND, response.getStatus());
            final MutableUri locationUri = getLocationUri(response);
            final Optional<String> responseJwtString = new Form().fromQueryString(locationUri.getQuery()).get(RESPONSE_PARAM).stream().findFirst();
            assertTrue(responseJwtString.isPresent());
            jwtReSignerTestResourceManager.validateJwtHasBeenReSigned(expectedResponseJwtJti, responseJwtString.get());

            final SignedJwt responseJwt = new JwtReconstruction().reconstructJwt(responseJwtString.get(), SignedJwt.class);
            if (expectedIdTokenJti != null) {
                final String idTokenStr = responseJwt.getClaimsSet().getClaim(ID_TOKEN, String.class);
                jwtReSignerTestResourceManager.validateIdTokenHasBeenReSigned(expectedIdTokenJti, idTokenStr);
            } else {
                assertTrue(responseJwt.getClaimsSet().get(ID_TOKEN).isNull(),
                        "id_token inside the response JWT must be null - if it is expected then supply the expectedIdTokenJti param to validate it");
            }
        }

        @Test
        void responseJwtAndNestedIdTokenAreReSigned() {
            final String responseJwtJti = UUID.randomUUID().toString();
            final String idTokenJti = UUID.randomUUID().toString();
            final String idToken = jwtReSignerTestResourceManager.createAmSignedIdToken(idTokenJti);
            final TestHandler responseHandler = new FixedResponseHandler(buildJwtResponse(responseJwtJti, idToken));
            final Request request = createAuthorizeRequestJwtResponseMode();

            final Response response = invokeFilter(createFilter(), request, responseHandler);

            validateSuccessJwtResponseModeResponse(response, responseJwtJti, idTokenJti);
        }

        @Test
        void testAmResponseWithoutResponseJwtIsPassedThrough() {
            final TestHandler responseHandler = new FixedResponseHandler(buildAuthoriseEndpointFragmentResponse("ignored"));

            final Response response = invokeFilter(createFilter(), createAuthorizeRequestJwtResponseMode(), responseHandler);
            assertEquals(Status.FOUND, response.getStatus());
        }

        @Test
        void testReSignerFailuresCauseInternalServerError() {
            final String responseJwtJti = UUID.randomUUID().toString();
            final String idTokenJti = UUID.randomUUID().toString();
            // id_token that has not been signed by AM and will therefore fail sig validation in the re-signer
            final String idTokenNotSignedByAm = jwtReSignerTestResourceManager.createSignedIdToken(tppJwtSigner, tppKeyId, idTokenJti);
            final TestHandler responseHandler = new FixedResponseHandler(buildJwtResponse(responseJwtJti, idTokenNotSignedByAm));

            final Response response = invokeFilter(createFilter(), createAuthorizeRequestJwtResponseMode(), responseHandler);

            assertEquals(Status.INTERNAL_SERVER_ERROR, response.getStatus());
        }

        private Response buildJwtResponse(String responseJwtJti, String idToken) {
            return buildAuthoriseEndpointResponse(false, buildJwtResponseModeFormParams(responseJwtJti, idToken));
        }

        private Form buildJwtResponseModeFormParams(String responseJwtJti, String idToken) {
            final Form form = new Form();
            form.add(RESPONSE_PARAM, buildResponseJwt(responseJwtJti, idToken));
            return form;
        }

        private String buildResponseJwt(String responseJwtJti, String idToken) {
            Map<String, Object> responseJwtClaims = new HashMap<>();
            responseJwtClaims.put(AUTHORISATION_CODE_PARAM, AUTHORISATION_CODE_VALUE);
            if (idToken != null) {
                responseJwtClaims.put(ID_TOKEN, idToken);
            }
            return jwtReSignerTestResourceManager.createAmSignedJwt(responseJwtJti, responseJwtClaims);
        }
    }

    private void validateSuccessAuthoriseQueryResponse(Response response, String expectedIdTokenJti) {
        assertEquals(Status.FOUND, response.getStatus());
        final MutableUri locationUri = getLocationUri(response);
        final Optional<String> idToken = new Form().fromQueryString(locationUri.getQuery()).get(ID_TOKEN).stream().findFirst();
        assertTrue(idToken.isPresent());
        jwtReSignerTestResourceManager.validateIdTokenHasBeenReSigned(expectedIdTokenJti, idToken.get());
    }

    private void validateSuccessAuthoriseFragmentResponse(Response response, String expectedIdTokenJti) {
        assertEquals(Status.FOUND, response.getStatus());
        final MutableUri locationUri = getLocationUri(response);
        final Optional<String> idToken = new Form().fromQueryString(locationUri.getFragment()).get(ID_TOKEN).stream().findFirst();
        assertTrue(idToken.isPresent());
        jwtReSignerTestResourceManager.validateIdTokenHasBeenReSigned(expectedIdTokenJti, idToken.get());
    }


    private static MutableUri getLocationUri(Response response) {
        final Header location = response.getHeaders().get("location");
        try {
            return MutableUri.uri(location.getFirstValue());
        } catch (URISyntaxException e) {
            throw new RuntimeException(e);
        }
    }
}