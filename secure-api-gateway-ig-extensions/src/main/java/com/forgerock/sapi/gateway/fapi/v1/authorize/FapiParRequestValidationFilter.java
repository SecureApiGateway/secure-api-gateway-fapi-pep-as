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
import static com.forgerock.sapi.gateway.common.jwt.AuthorizeRequestParameterNames.CODE_CHALLENGE;
import static com.forgerock.sapi.gateway.common.jwt.AuthorizeRequestParameterNames.CODE_CHALLENGE_METHOD;
import static com.forgerock.sapi.gateway.common.jwt.AuthorizeRequestParameterNames.NONCE;
import static com.forgerock.sapi.gateway.common.jwt.AuthorizeRequestParameterNames.REDIRECT_URI;
import static com.forgerock.sapi.gateway.common.jwt.AuthorizeRequestParameterNames.RESPONSE_TYPE;
import static com.forgerock.sapi.gateway.common.jwt.AuthorizeRequestParameterNames.SCOPE;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

import org.forgerock.http.protocol.Header;
import org.forgerock.http.protocol.Request;
import org.forgerock.http.protocol.Response;
import org.forgerock.json.jose.jwt.JwtClaimsSet;
import org.forgerock.openig.heap.GenericHeaplet;
import org.forgerock.openig.heap.HeapException;
import org.forgerock.util.promise.NeverThrowsException;
import org.forgerock.util.promise.Promise;

/**
 * Validates that a request made to the OAuth2.0 /par (Pushed Authorization Request) endpoint is FAPI compliant.
 * <p>
 * For /par requests, the request JWT is supplied as an HTTP Form parameter.
 * <p>
 * For more details see:
 * <a href="https://datatracker.ietf.org/doc/html/rfc9126#name-pushed-authorization-reques">OAuth 2.0 Pushed Authorization Requests</a>
 */
public class FapiParRequestValidationFilter extends BaseFapiAuthorizeRequestValidationFilter {

    private static final List<String> REQUIRED_REQUEST_JWT_CLAIMS = List.of(SCOPE, NONCE, RESPONSE_TYPE, REDIRECT_URI,
            CLIENT_ID, CODE_CHALLENGE, CODE_CHALLENGE_METHOD);

    private static final String VALID_CODE_CHALLENGE_METHOD = "S256";

    /**
     * Retrieves parameters from the HTTP Request's Form
     *
     * @param request   Request the HTTP Request to retrieve the parameter from
     * @param paramName String the name of the parameter
     * @return Promise<String, NeverThrowsException> a promise containing the String value of the parameter or null if
     * the parameter does not exist or if an exception is thrown.
     */
    @Override
    protected Promise<String, NeverThrowsException> getParamFromRequest(Request request, String paramName) {
        return request.getEntity().getFormAsync()
                .then(form -> form.getFirst(paramName))
                .thenCatch(ioe -> {
                    logger.warn("Failed to extract data from /par request due to exception", ioe);
                    return null;
                });
    }

    @Override
    protected List<String> getRequiredRequestJwtClaims() {
        return REQUIRED_REQUEST_JWT_CLAIMS;
    }

    /**
     * For the PAR endpoint we need to check that the CODE_CHALLENGE_METHOD is S256
     * @param acceptHeader - determines response media type
     * @param requestJwtClaimSet - the claims found in the JAR object
     */
    @Override
    protected Response checkEndpointSpecificClaims(Header acceptHeader, JwtClaimsSet requestJwtClaimSet) {
        String codeChallengeMethod = requestJwtClaimSet.get(CODE_CHALLENGE_METHOD).asString();
        if(!codeChallengeMethod.equals(VALID_CODE_CHALLENGE_METHOD)) {
            return errorResponseFactory.invalidRequestErrorResponse(acceptHeader, "Request JWT must have a " +
                    "'code_challenge_method' claim of S256");
        }
        return null;
    }

    @Override
    protected Promise<List<String>, NeverThrowsException> removeNonMatchingParamsFromRequest(Request request,
            List<String> paramNamesToKeep) {
        return request.getEntity().getFormAsync().then(
                form -> {
                    List<String> paramsRemoved = new ArrayList<>();
                    Iterator<String> itt = form.keySet().iterator();
                    while(itt.hasNext()){
                        String key = itt.next();
                        if(!paramNamesToKeep.contains(key)){
                            itt.remove();
                            paramsRemoved.add(key);
                            logger.debug("Removed form parameter '{}' from PAR request", itt);
                        }
                    }
                    request.setEntity(form);
                    return paramsRemoved;
                }, ioe -> {
                    logger.warn("Failed to remove param from /par request form due to exception", ioe);
                    List<String> emptyList = new ArrayList<>();
                    return emptyList;
                });
    }

    public static class Heaplet extends GenericHeaplet {
        @Override
        public Object create() throws HeapException {
            return new FapiParRequestValidationFilter();
        }
    }
}
