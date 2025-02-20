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
package com.forgerock.sapi.gateway.dcr.filter;

import static com.forgerock.sapi.gateway.dcr.filter.ResponsePathFetchApiClientFilter.createFilterWithRequestClientIdRetriever;
import static org.forgerock.openig.util.JsonValues.requiredHeapObject;

import java.util.List;
import java.util.function.Function;

import org.forgerock.http.protocol.Request;
import org.forgerock.openig.fapi.apiclient.ApiClient;
import org.forgerock.openig.fapi.apiclient.service.ApiClientService;
import org.forgerock.openig.heap.GenericHeaplet;
import org.forgerock.openig.heap.HeapException;
import org.forgerock.util.promise.NeverThrowsException;
import org.forgerock.util.promise.Promise;
import org.forgerock.util.promise.Promises;

/**
 * Responsible for creating a {@link ResponsePathFetchApiClientFilter} that can be used to protect calls to an
 * OAuth2.0 authorize endpoint, the filter is configured to retrieve the client_id from the request's query parameter
 * of the same name.
 * <p>
 * Mandatory config:
 * - apiClientService: reference to an {@link ApiClientService} implementation heap object to use to retrieve the {@link ApiClient}
 * <p>
 * Example config:
 * <pre>{@code
 * {
 *   "comment": "Add ApiClient data to the context attributes for the AS /authorize route",
 *   "name": "AuthoriseResponseFetchApiClientFilter",
 *   "type": "AuthoriseResponseFetchApiClientFilter",
 *   "config": {
 *     "apiClientService": "IdmApiClientService"
 *   }
 * }
 * }</pre>
 */
public class AuthorizeResponseFetchApiClientFilterHeaplet extends GenericHeaplet {

    /**
     * Helper function capable of retrieving the client_id parameter from the Request's Query params.
     *
     * @return Promise<String, NeverThrowsException> which returns the client_id or null if it does not exist
     */
    static Function<Request, Promise<String, NeverThrowsException>> queryParamClientIdRetriever() {
        return request -> {
            final List<String> clientIdParams = request.getQueryParams().get("client_id");
            if (clientIdParams != null && !clientIdParams.isEmpty()) {
                return Promises.newResultPromise(clientIdParams.get(0));
            } else {
                return Promises.newResultPromise(null);
            }
        };
    }

    @Override
    public Object create() throws HeapException {
        final ApiClientService apiClientService = config.get("apiClientService")
                                                        .as(requiredHeapObject(heap, ApiClientService.class));

        return createFilterWithRequestClientIdRetriever(apiClientService, queryParamClientIdRetriever());
    }
}
