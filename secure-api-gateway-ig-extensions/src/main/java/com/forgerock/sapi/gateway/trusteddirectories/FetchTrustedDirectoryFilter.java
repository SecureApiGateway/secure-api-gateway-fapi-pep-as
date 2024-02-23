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
package com.forgerock.sapi.gateway.trusteddirectories;

import static org.forgerock.openig.util.JsonValues.requiredHeapObject;

import org.forgerock.http.Filter;
import org.forgerock.http.Handler;
import org.forgerock.http.protocol.Request;
import org.forgerock.http.protocol.Response;
import org.forgerock.openig.heap.GenericHeaplet;
import org.forgerock.openig.heap.HeapException;
import org.forgerock.services.context.AttributesContext;
import org.forgerock.services.context.Context;
import org.forgerock.util.Reject;
import org.forgerock.util.promise.NeverThrowsException;
import org.forgerock.util.promise.Promise;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.forgerock.sapi.gateway.dcr.filter.FetchApiClientFilter;
import com.forgerock.sapi.gateway.dcr.models.ApiClient;

/**
 * Fetches {@link TrustedDirectory} configuration for the {@link ApiClient} that is configured in the {@link AttributesContext}
 * and adds the TrustedDirectory to the attributes context so that it can be used by subsequent filters.
 *
 * This filter must be installed after a filter which adds the ApiClient to the context, typically: {@link FetchApiClientFilter}
 */
public class FetchTrustedDirectoryFilter implements Filter {

    /**
     * The key to use to get the TrustedDirectory from the AttributesContext
     */
    public static final String TRUSTED_DIRECTORY_ATTR_KEY = "trustedDirectory";

    private final Logger logger = LoggerFactory.getLogger(getClass());

    /**
     * The Service used to retrieve the TrustedDirectory
     */
    private final TrustedDirectoryService trustedDirectoryService;

    /**
     * Utility method to retrieve a TrustedDirectory object from a Context.
     * This method can be used by other filters to retrieve the TrustedDirectory installed into the attributes context by
     * this filter.
     *
     * @param context the context to retrieve the TrustedDirectory from
     * @return the TrustedDirectory or null if it is not set in the context.
     */
    public static TrustedDirectory getTrustedDirectoryFromContext(Context context) {
        return (TrustedDirectory) context.asContext(AttributesContext.class).getAttributes().get(TRUSTED_DIRECTORY_ATTR_KEY);
    }

    public FetchTrustedDirectoryFilter(TrustedDirectoryService trustedDirectoryService) {
        Reject.ifNull(trustedDirectoryService, "trustedDirectoryService must be provided");
        this.trustedDirectoryService = trustedDirectoryService;
    }

    @Override
    public Promise<Response, NeverThrowsException> filter(Context context, Request request, Handler next) {
        final ApiClient apiClient = FetchApiClientFilter.getApiClientFromContext(context);
        if (apiClient == null) {
            logger.error("apiClient not found in request context");
            throw new IllegalStateException("apiClient not found in request context");
        }
        try {
            context.asContext(AttributesContext.class).getAttributes().put(TRUSTED_DIRECTORY_ATTR_KEY, getTrustedDirectory(apiClient));
            return next.handle(context, request);
        } catch (RuntimeException ex) {
            logger.error("Failed to get trustedDirectory for apiClient: " + apiClient, ex);
            throw ex;
        }
    }

    private TrustedDirectory getTrustedDirectory(ApiClient apiClient) {
        final TrustedDirectory trustedDirectory = trustedDirectoryService.getTrustedDirectoryConfiguration(apiClient);
        if (trustedDirectory == null) {
            throw new IllegalStateException("Failed to get trusted directory for apiClient: " + apiClient);
        }
        return trustedDirectory;
    }

    /**
     * Responsible for creating the {@link FetchTrustedDirectoryFilter}
     *
     * Mandatory config:
     * - trustedDirectoryService: the name of a {@link TrustedDirectoryService} object on the heap
     *
     * Example config:
     * {
     *             "comment": "Add TrustedDirectory configuration to the context attributes",
     *             "name": "FetchTrustedDirectoryFilter",
     *             "type": "FetchTrustedDirectoryFilter",
     *             "config": {
     *               "trustedDirectoryService": "TrustedDirectoriesService"
     *             }
     * }
     */
    public static class Heaplet extends GenericHeaplet {
        @Override
        public Object create() throws HeapException {
            final TrustedDirectoryService trustedDirectoryService = config.get("trustedDirectoryService")
                    .as(requiredHeapObject(heap, TrustedDirectoryService.class));

            return new FetchTrustedDirectoryFilter(trustedDirectoryService);
        }
    }
}
