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

import java.io.IOException;

import org.forgerock.http.protocol.Form;
import org.forgerock.http.protocol.Request;
import org.forgerock.openig.heap.HeapException;

class FapiParRequestValidationFilterTest extends BaseFapiAuthorizeRequestValidationFilterTest {

    public FapiParRequestValidationFilterTest() throws HeapException {
        super((FapiParRequestValidationFilter) new FapiParRequestValidationFilter.Heaplet().create());
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
}