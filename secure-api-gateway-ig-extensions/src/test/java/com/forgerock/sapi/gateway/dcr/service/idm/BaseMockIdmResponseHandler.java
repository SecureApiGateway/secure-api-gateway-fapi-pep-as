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
package com.forgerock.sapi.gateway.dcr.service.idm;

import java.net.URISyntaxException;

import org.forgerock.http.Handler;
import org.forgerock.http.MutableUri;
import org.forgerock.http.protocol.Request;
import org.forgerock.http.protocol.Response;
import org.forgerock.http.protocol.Status;
import org.forgerock.json.JsonValue;
import org.forgerock.services.context.Context;
import org.forgerock.util.promise.NeverThrowsException;
import org.forgerock.util.promise.Promise;
import org.forgerock.util.promise.Promises;

/**
 * Mocks the responses from IDM.
 * <p>
 * Validates that IDM is called with the expected Request and returns a pre-canned Response with a json Entity.
 * <p>
 * If the validation fails then a Runtime exception is returned, which will be thrown when Promise.get is called.
 */
public abstract class BaseMockIdmResponseHandler implements Handler {
    protected final MutableUri idmBaseUri;
    protected final JsonValue responseJson;

    public BaseMockIdmResponseHandler(String idmBaseUri, String managedObjectName, JsonValue responseJson) {
        try {
            this.idmBaseUri = MutableUri.uri(idmBaseUri + "/" + managedObjectName);
        } catch (URISyntaxException e) {
            throw new RuntimeException(e);
        }
        this.responseJson = responseJson;
    }

    @Override
    public Promise<Response, NeverThrowsException> handle(Context context, Request request) {
        if (isValidRequest(request)) {
            final Response idmResponse = createResponse();
            return Promises.newResultPromise(idmResponse);
        }
        return Promises.newRuntimeExceptionPromise(
                new IllegalStateException("Unexpected request - method: " + request.getMethod()
                        + ", uri: " + request.getUri() + ", entity: " + request.getEntity()));
    }

    protected Response createResponse() {
        Response idmResponse = new Response(Status.OK);
        idmResponse.setEntity(responseJson);
        return customiseResponse(idmResponse);
    }

    // Hook to allow subclasses to customise the Response, does nothing by default
    protected Response customiseResponse(Response response) {
        return response;
    }


    abstract boolean isValidRequest(Request request);

}
