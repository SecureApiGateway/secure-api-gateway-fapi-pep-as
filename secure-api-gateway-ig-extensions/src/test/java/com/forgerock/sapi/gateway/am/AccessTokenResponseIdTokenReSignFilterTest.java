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
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.util.UUID;

import org.forgerock.http.protocol.Form;
import org.forgerock.http.protocol.Request;
import org.forgerock.http.protocol.Response;
import org.forgerock.http.protocol.Status;
import org.forgerock.json.JsonValue;
import org.forgerock.openig.heap.HeapImpl;
import org.forgerock.openig.heap.Name;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import com.forgerock.sapi.gateway.am.AccessTokenResponseIdTokenReSignFilter.Heaplet;
import com.forgerock.sapi.gateway.util.CryptoUtils;
import com.forgerock.sapi.gateway.util.TestHandlers.FixedResponseHandler;
import com.forgerock.sapi.gateway.util.TestHandlers.TestHandler;
import com.nimbusds.jose.crypto.RSASSASigner;

class AccessTokenResponseIdTokenReSignFilterTest {

    private static final String ACCESS_TOKEN_VALUE = "access-token-123";
    private static final String SCOPE_VALUE = "openid payments";
    private static final String TOKEN_TYPE_VALUE = "Bearer";
    private static final int EXPIRES_IN_VALUE = 359999;
    private static final String ACCESS_TOKEN = "access_token";
    private static final String SCOPE = "scope";
    private static final String ID_TOKEN = "id_token";
    private static final String TOKEN_TYPE = "token_type";
    private static final String EXPIRES_IN = "expires_in";

    private final JwtReSignerTestResourceManager jwtReSignerTestResourceManager;
    private final JwtReSigner jwtReSigner;

    public AccessTokenResponseIdTokenReSignFilterTest() {
        jwtReSignerTestResourceManager = new JwtReSignerTestResourceManager();
        jwtReSigner = jwtReSignerTestResourceManager.getJwtReSigner();
    }

    private AccessTokenResponseIdTokenReSignFilter createFilter() {
        return new AccessTokenResponseIdTokenReSignFilter(jwtReSigner);
    }

    private static Response buildAccessTokenEndpointResponse(String idToken) {
        return new Response(Status.OK).setEntity(json(object(
                field(ACCESS_TOKEN, ACCESS_TOKEN_VALUE),
                field(SCOPE, SCOPE_VALUE),
                field(ID_TOKEN, idToken),
                field(TOKEN_TYPE, TOKEN_TYPE_VALUE),
                field(EXPIRES_IN, EXPIRES_IN_VALUE)

        )));
    }

    private static JsonValue validateResponseJwtNonIdTokenFields(Response response) throws IOException {
        final JsonValue json = json(response.getEntity().getJson());
        assertTrue(json.isMap());
        // Valid non id_token fields in AM response are untouched by the filter
        assertEquals(ACCESS_TOKEN_VALUE, json.get(ACCESS_TOKEN).asString());
        assertEquals(SCOPE_VALUE, json.get(SCOPE).asString());
        assertEquals(TOKEN_TYPE_VALUE, json.get(TOKEN_TYPE).asString());
        assertEquals(EXPIRES_IN_VALUE, json.get(EXPIRES_IN).asInteger());
        return json;
    }

    private void validateSuccessResponseJwt(Response response, String expectedIdTokenJti) {
        assertEquals(Status.OK, response.getStatus());
        try {
            final JsonValue json = validateResponseJwtNonIdTokenFields(response);

            final String idToken = json.get(ID_TOKEN).asString();
            jwtReSignerTestResourceManager.validateIdTokenHasBeenReSigned(expectedIdTokenJti, idToken);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    @Test
    void testAccessTokenEndpointIdTokenIsReSigned() {
        testAccessTokenEndpointIdTokenIsReSigned(createFilter());
    }

    private void testAccessTokenEndpointIdTokenIsReSigned(AccessTokenResponseIdTokenReSignFilter filter) {
        final String expectedJti = UUID.randomUUID().toString();
        final TestHandler responseHandler = new FixedResponseHandler(buildAccessTokenEndpointResponse(jwtReSignerTestResourceManager.createAmSignedIdToken(expectedJti)));

        final Response response = invokeFilter(filter, new Request(), responseHandler);

        validateSuccessResponseJwt(response, expectedJti);
    }

    @Test
    void testAmErrorResponsesArePassedThrough()  {
        final TestHandler responseHandler = new FixedResponseHandler(new Response(Status.BAD_REQUEST));

        final Response response = invokeFilter(createFilter(), new Request(), responseHandler);
        assertEquals(Status.BAD_REQUEST, response.getStatus());
    }

    @Test
    void testAccessTokenResponsesWithNoIdTokenArePassedThrough() throws IOException {
        final TestHandler responseHandler = new FixedResponseHandler(buildAccessTokenEndpointResponse(null));

        final Response response = invokeFilter(createFilter(), new Request(), responseHandler);

        assertEquals(Status.OK, response.getStatus());
        validateResponseJwtNonIdTokenFields(response);
        assertTrue(json(response.getEntity().getJson()).get("id_token").isNull());
    }

    @Test
    void testAccessTokenResponseNotJsonRaisesError() {
        // Form response instead of json
        final TestHandler responseHandler = new FixedResponseHandler(new Response(Status.OK).setEntity(new Form().fromQueryString("key=value")));

        final Response response = invokeFilter(createFilter(), new Request(), responseHandler);
        assertEquals(Status.INTERNAL_SERVER_ERROR, response.getStatus());
    }

    @Test
    void testIdTokensNotSignedCorrectlyRaisesError() {
        final String expectedJti = UUID.randomUUID().toString();

        final RSASSASigner signerWithUnknownKey = new RSASSASigner(CryptoUtils.generateRsaKeyPair().getPrivate());
        final TestHandler responseHandler = new FixedResponseHandler(buildAccessTokenEndpointResponse(
                jwtReSignerTestResourceManager.createSignedIdToken(signerWithUnknownKey, "kid-123", expectedJti)));

        final Response response = invokeFilter(createFilter(), new Request(), responseHandler);
        assertEquals(Status.INTERNAL_SERVER_ERROR, response.getStatus());
    }

    @Nested
    public class HeapletTests {
        @Test
        void createFilterUsingHeaplet() throws Exception {
            final Heaplet heaplet = new Heaplet();
            final HeapImpl heap = new HeapImpl(Name.of("heap"));
            heap.put("jwtReSigner", jwtReSigner);
            final AccessTokenResponseIdTokenReSignFilter filter = (AccessTokenResponseIdTokenReSignFilter) heaplet.create(Name.of("test"), json(object(field("jwtReSigner", "jwtReSigner"))), heap);
            testAccessTokenEndpointIdTokenIsReSigned(filter);

        }

    }

}