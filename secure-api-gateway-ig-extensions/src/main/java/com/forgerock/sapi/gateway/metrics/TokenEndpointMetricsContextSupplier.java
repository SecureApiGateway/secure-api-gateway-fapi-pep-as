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
package com.forgerock.sapi.gateway.metrics;

import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.forgerock.http.protocol.Form;
import org.forgerock.http.protocol.Request;
import org.forgerock.openig.heap.GenericHeaplet;
import org.forgerock.openig.heap.HeapException;
import org.forgerock.services.context.Context;
import org.forgerock.util.promise.NeverThrowsException;
import org.forgerock.util.promise.Promise;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Supplies Context information for the Token Endpoint route.
 * <p>
 * The following data is extracted from the Request's form:
 * <ul>
 *     <li>"grant_type this represents the OAuth2.0 grant_type of the token that is being requested.</li>
 *     <li>"scope" this represents the OAuth2.0 scopes that are being requested.</li>
 * </ul>
 */
public class TokenEndpointMetricsContextSupplier implements MetricsContextSupplier {

    private static final String GRANT_TYPE = "grant_type";
    private static final String SCOPE = "scope";

    private final Logger logger = LoggerFactory.getLogger(getClass());

    @Override
    public Promise<Map<String, Object>, NeverThrowsException> getMetricsContext(Context requestContext, Request request) {
        return request.getEntity().getFormAsync().then(form -> {
            final Map<String, Object> context = new HashMap<>();
            final String grantType = getGrantType(form);
            if (grantType != null) {
                context.put(GRANT_TYPE, grantType);
            }
            final List<String> scopes = getScopes(form);
            if (scopes != null && !scopes.isEmpty()) {
                context.put(SCOPE, scopes);
            }
            return context;
        }, ioe -> {
            logger.error("Failed to extract metrics context data from request form", ioe);
            return Collections.emptyMap();
        });
    }

    private String getGrantType(Form form) {
        return getSingleFormValue(form, GRANT_TYPE);
    }

    private List<String> getScopes(Form form) {
        final String scopeParam = getSingleFormValue(form, SCOPE);
        if (scopeParam != null) {
            return Arrays.asList(scopeParam.split("\\s+"));
        }
        return null;
    }

    private String getSingleFormValue(Form form, String paramName) {
        final List<String> params = form.get(paramName);
        if (params != null && !params.isEmpty()) {
            return params.get(0);
        }
        return null;
    }

    public static class Heaplet extends GenericHeaplet {
        @Override
        public Object create() throws HeapException {
            return new TokenEndpointMetricsContextSupplier();
        }
    }
}
