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
package com.forgerock.sapi.gateway.dcr.filter;

import static com.forgerock.sapi.gateway.dcr.filter.AuthorizeResponseFetchApiClientFilter.queryParamClientIdRetriever;
import static org.forgerock.openig.util.JsonValues.requiredHeapObject;

import org.forgerock.openig.heap.GenericHeaplet;
import org.forgerock.openig.heap.HeapException;

import com.forgerock.sapi.gateway.dcr.models.ApiClient;
import com.forgerock.sapi.gateway.dcr.service.ApiClientService;

/**
 * Responsible for creating the {@link AuthorizeResponseFetchApiClientFilter}
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

    @Override
    public Object create() throws HeapException {
        final ApiClientService apiClientService = config.get("apiClientService").as(requiredHeapObject(heap, ApiClientService.class));
        return new AuthorizeResponseFetchApiClientFilter(apiClientService, queryParamClientIdRetriever());
    }
}
