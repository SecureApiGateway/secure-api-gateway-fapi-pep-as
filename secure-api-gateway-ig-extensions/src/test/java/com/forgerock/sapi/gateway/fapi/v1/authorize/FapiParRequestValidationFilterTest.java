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

import static com.forgerock.sapi.gateway.common.jwt.AuthorizeRequestParameterNames.CODE_CHALLENGE;
import static com.forgerock.sapi.gateway.common.jwt.AuthorizeRequestParameterNames.CODE_CHALLENGE_METHOD;

import java.io.IOException;
import java.util.HashMap;
import java.util.UUID;

import org.forgerock.http.protocol.Form;
import org.forgerock.http.protocol.Request;
import org.forgerock.http.protocol.Response;
import org.forgerock.openig.heap.HeapException;
import org.forgerock.util.promise.NeverThrowsException;
import org.forgerock.util.promise.Promise;
import org.junit.jupiter.api.Test;

import com.nimbusds.jwt.JWTClaimsSet;

class FapiParRequestValidationFilterTest extends BaseFapiAuthorizeRequestValidationFilterTest {

    private JWTSigner jwtSigner = new JWTSigner();

    private String VALID_CODE_CHALLENGE = "SGVsbG8gV29ybGQh";
    private String VALID_CODE_CHALLENGE_METHOD = "S256";


    public FapiParRequestValidationFilterTest() throws HeapException {
        super((FapiParRequestValidationFilter) new FapiParRequestValidationFilter.Heaplet().create());
    }

    @Test
    void failsForParRequestWithoutPkceCodeChallenge() throws Exception {
        final String state = UUID.randomUUID().toString();
        HashMap<String, Object> jarClaims = getEndpointSpecificMapOfClaims();
        jarClaims.remove(CODE_CHALLENGE);
        final JWTClaimsSet requestClaims = JWTClaimsSet.parse(jarClaims);
        final String signedRequestJwt = jwtSigner.createSignedRequestJwt(requestClaims);

        final Request request = createRequest(signedRequestJwt, state);

        final Promise<Response, NeverThrowsException> responsePromise = filter.filter(context, request, successResponseHandler);
        validateErrorResponse(responsePromise, "Request JWT must have a 'code_challenge' claim");
    }

    @Test
    void failsForParRequestWithoutPkceCodeChallengeMethodOfS256() throws Exception {
        final String state = UUID.randomUUID().toString();
        HashMap<String, Object> jarClaims = getEndpointSpecificMapOfClaims();
        jarClaims.put(CODE_CHALLENGE_METHOD, "PS256");
        final JWTClaimsSet requestClaims = JWTClaimsSet.parse(jarClaims);
        final String signedRequestJwt = jwtSigner.createSignedRequestJwt(requestClaims);

        final Request request = createRequest(signedRequestJwt, state);

        final Promise<Response, NeverThrowsException> responsePromise = filter.filter(context, request, successResponseHandler);
        validateErrorResponse(responsePromise, "Request JWT must have a 'code_challenge_method' claim of S256");
    }

    @Override
    protected Request createRequest(String requestJwt, String state) throws Exception {
        final Request request = new Request();
        request.setMethod("POST");
        request.setUri("https://localhost/am/par");
        final Form form = new Form();
        form.putSingle("state", state);
        form.putSingle("request", requestJwt);
        request.setEntity(form);
        return request;
    }

    @Override
    protected String getRequestState(Request request) {
        try {
            return request.getEntity().getForm().getFirst("state");
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * PAR request requires SCOPE, NONCE, RESPONSE_TYPE, REDIRECT_URI,
     *             CLIENT_ID, CODE_CHALLENGE, CODE_CHALLENGE_METHOD
     * @return {@code Map<String, String} containing valid claims for a FAPI 1.0 - Part 2: Advanced compliant PAR
     * JAR object
     */
    @Override
    protected HashMap<String, Object> getEndpointSpecificMapOfClaims() {
        HashMap<String, Object> validBaseClaims = getCommonMapOfClaims();
        validBaseClaims.put(CODE_CHALLENGE, VALID_CODE_CHALLENGE);
        validBaseClaims.put(CODE_CHALLENGE_METHOD, VALID_CODE_CHALLENGE_METHOD);
        return validBaseClaims;
    }
}