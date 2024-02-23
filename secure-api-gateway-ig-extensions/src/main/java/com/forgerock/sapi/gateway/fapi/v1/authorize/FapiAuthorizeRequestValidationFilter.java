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

import java.util.List;

import org.forgerock.http.Handler;
import org.forgerock.http.protocol.Form;
import org.forgerock.http.protocol.Request;
import org.forgerock.http.protocol.Response;
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

    @Override
    public Promise<Response, NeverThrowsException> filter(Context context, Request request, Handler next) {
        // Allow /authorize requests that are for PAR to continue, request JWT is supplied and validated when calling /par endpoint
        if (isAuthorizeParRequest(request)) {
            logger.debug("/authorize request is for a /par request, skipping request JWT validation");
            return next.handle(context, request);
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

    /**
     * Removes the state parameter from the Request's Query parameters
     * @param request Request the HTTP Request to remove the state param from.
     */
    @Override
    protected void removeStateParamFromRequest(Request request) {
        final Form existingQueryParams = request.getQueryParams();
        existingQueryParams.remove(STATE_PARAM_NAME);
        existingQueryParams.toRequestQuery(request);
    }

    public static class Heaplet extends GenericHeaplet {
        @Override
        public Object create() throws HeapException {
            return new FapiAuthorizeRequestValidationFilter();
        }
    }

}
