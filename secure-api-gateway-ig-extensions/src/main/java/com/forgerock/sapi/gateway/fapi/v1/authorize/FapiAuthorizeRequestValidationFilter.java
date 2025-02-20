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
package com.forgerock.sapi.gateway.fapi.v1.authorize;

import static com.forgerock.sapi.gateway.common.jwt.AuthorizeRequestParameterNames.CLIENT_ID;
import static com.forgerock.sapi.gateway.common.jwt.AuthorizeRequestParameterNames.NONCE;
import static com.forgerock.sapi.gateway.common.jwt.AuthorizeRequestParameterNames.REDIRECT_URI;
import static com.forgerock.sapi.gateway.common.jwt.AuthorizeRequestParameterNames.RESPONSE_TYPE;
import static com.forgerock.sapi.gateway.common.jwt.AuthorizeRequestParameterNames.SCOPE;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

import org.forgerock.http.Handler;
import org.forgerock.http.protocol.Form;
import org.forgerock.http.protocol.Header;
import org.forgerock.http.protocol.Request;
import org.forgerock.http.protocol.Response;
import org.forgerock.json.jose.jwt.JwtClaimsSet;
import org.forgerock.openig.heap.GenericHeaplet;
import org.forgerock.openig.heap.HeapException;
import org.forgerock.services.context.Context;
import org.forgerock.util.promise.NeverThrowsException;
import org.forgerock.util.promise.Promise;
import org.forgerock.util.promise.Promises;

/**
 * Validates that a request made to the OAuth2.0 /authorize endpoint is FAPI compliant.
 * <p>
 * For /authorize requests, the request JWT is supplied as an HTTP Query Param
 * <p>
 * For more details on /authorize requests see: <a href="https://www.rfc-editor.org/rfc/rfc6749#section-4.1">OAuth 2.0 spec</a>
 */
public class FapiAuthorizeRequestValidationFilter extends BaseFapiAuthorizeRequestValidationFilter {

    private static final String REQUEST_URI_PARAM_NAME = "request_uri";
    private static final List<String> REQUIRED_REQUEST_JWT_CLAIMS = List.of(SCOPE, NONCE, RESPONSE_TYPE, REDIRECT_URI,
            CLIENT_ID);

    @Override
    public Promise<Response, NeverThrowsException> filter(Context context, Request request, Handler next) {
        // Allow /authorize requests that are for PAR to continue, request JWT is supplied and validated when calling /par endpoint
        if (isAuthorizeParRequest(request)) {
            logger.debug("/authorize request is for a /par request no validation of ");

            // Remove parameters that should be ignored from the http request - parameters should only be read from
            // the JAR object
            return removeParamsFromRequest(request)
                    .thenAsync(noResult -> {
                        logger.info("Authorize request is FAPI compliant");
                        return next.handle(context, request);
                    });

        }
        return super.filter(context, request, next);
    }

    /**
     * Requests which contain a request_uri param are /authorize requests for a previously submitted /par request.
     * <p>
     * See: <a href="https://datatracker.ietf.org/doc/html/rfc9126#name-authorization-request">OAuth 2.0 PAR authorization request</a>
     *
     * @param request Request to check
     * @return boolean indicating if this is an authorize request for a par request
     */
    private boolean isAuthorizeParRequest(Request request) {
        return getParamFromRequestQuery(request, REQUEST_URI_PARAM_NAME) != null;
    }

    /**
     * Implementation which retrieves parameter values from the HTTP Request's Query Parameters
     */
    @Override
    protected Promise<String, NeverThrowsException> getParamFromRequest(Request request, String paramName) {
        return Promises.newResultPromise(getParamFromRequestQuery(request, paramName));
    }

    @Override
    protected List<String> getRequiredRequestJwtClaims() {
        return REQUIRED_REQUEST_JWT_CLAIMS;
    }

    @Override
    protected Response checkEndpointSpecificClaims(Header acceptHeader, JwtClaimsSet requestJwtClaimSet) {
        return null;
    }

    /**
     * Implementation which removes parameter values that don't match an entry in paramNamesToKeep from the HTTP
     * Request's Query Parameters
     *
     * @param request          the request from which to remove the HTTP Request's query parameters
     * @param paramNamesToKeep the list of HTTP Request parameters to keep
     */
    @Override
    protected Promise<List<String>, NeverThrowsException> removeNonMatchingParamsFromRequest(Request request,
            List<String> paramNamesToKeep) {

        final Form existingQueryParams = request.getQueryParams();

        List<String> namesToRemove = new ArrayList<>();
        Iterator<String> iterator = existingQueryParams.keySet().iterator();
        while (iterator.hasNext()) {
            String formParamKey = iterator.next();
            if (!paramNamesToKeep.contains(formParamKey)) {
                namesToRemove.add(formParamKey);
                iterator.remove();
                logger.debug("Removed form parameter '{}' from PAR request", formParamKey);
            }
        }

        existingQueryParams.toRequestQuery(request);
        return Promises.newResultPromise(namesToRemove);
    }

    private String getParamFromRequestQuery(Request request, String paramName) {
        logger.debug("Obtaining query param with name '{}' from request", paramName);
        final List<String> value = request.getQueryParams().get(paramName);
        if (value == null) {
            logger.info("No query parameter of name '{}' exists in the request", paramName);
            return null;
        }
        if (value.size() != 1) {
            logger.info("There are '{}' values for request parameter '{}'", value.size(), paramName);
            return null;
        }
        logger.debug("Value of query param '{}' is '{}'", paramName, value);
        return value.get(0);
    }

    public static class Heaplet extends GenericHeaplet {
        @Override
        public Object create() throws HeapException {
            return new FapiAuthorizeRequestValidationFilter();
        }
    }

}
