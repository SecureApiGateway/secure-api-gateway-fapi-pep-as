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

import org.forgerock.http.protocol.Request;
import org.forgerock.http.protocol.Response;
import org.forgerock.openig.heap.HeapException;
import org.forgerock.util.promise.NeverThrowsException;
import org.forgerock.util.promise.Promise;
import org.junit.jupiter.api.Test;

import com.forgerock.sapi.gateway.fapi.v1.authorize.FapiAuthorizeRequestValidationFilter.Heaplet;

class FapiAuthorizeRequestValidationFilterTest extends BaseFapiAuthorizeRequestValidationFilterTest {

    FapiAuthorizeRequestValidationFilterTest() throws HeapException {
        super((FapiAuthorizeRequestValidationFilter) new Heaplet().create());
    }

    @Test
    void succeedsForAuthorizeRequestsUsingPar() throws Exception {
        // Test calling /authorize with a request_uri of a previously submitted /par request
        final Request request = new Request();
        request.setUri("https://localhost/am/authorize?request_uri=ref-to-par-req");
        request.setMethod("GET");

        final Promise<Response, NeverThrowsException> responsePromise = filter.filter(context, request, successResponseHandler);

        validateSuccessResponse(responsePromise);
        validateHandlerReceivedRequestWithoutStateParam();
    }

    @Override
    protected Request createRequest(String requestJwt, String state) throws Exception {
        final Request request = new Request();
        request.setUri("https://localhost/am/authorize?request=" + requestJwt + "&state=" + state);
        request.setMethod("GET");
        return request;
    }

    @Override
    protected String getRequestState(Request request) {
        final List<String> state = request.getQueryParams().get("state");
        return state != null ? state.get(0) : null;
    }
}