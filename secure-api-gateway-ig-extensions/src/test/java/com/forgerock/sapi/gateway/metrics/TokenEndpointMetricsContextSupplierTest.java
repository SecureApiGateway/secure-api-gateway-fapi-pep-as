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
package com.forgerock.sapi.gateway.metrics;

import static org.assertj.core.api.Assertions.*;

import java.util.List;
import java.util.Map;

import org.forgerock.http.protocol.Form;
import org.forgerock.http.protocol.Request;
import org.forgerock.openig.heap.HeapException;
import org.forgerock.services.context.Context;
import org.forgerock.services.context.RootContext;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import com.forgerock.sapi.gateway.metrics.TokenEndpointMetricsContextSupplier.Heaplet;


class TokenEndpointMetricsContextSupplierTest {

    // The Context is ignored by the supplier
    private final Context httpRequestContext = new RootContext("test");

    private TokenEndpointMetricsContextSupplier tokenEndpointMetricsContextSupplier;

    @BeforeEach
    void beforeEach() {
        try {
            tokenEndpointMetricsContextSupplier = (TokenEndpointMetricsContextSupplier) new Heaplet().create();
        } catch (HeapException e) {
            throw new RuntimeException(e);
        }
    }

    @Test
    void populatesContextFromValidRequest() {
        final String expectedGrantType = "client_credentials";

        final Request request = new Request();
        final Form form = new Form();
        form.put("client_id", List.of("1232"));
        form.put("something_else", List.of("blah", "blah"));
        form.put("grant_type", List.of(expectedGrantType));
        form.put("scope", List.of("payments openid"));
        form.put("another_thing", List.of("ldfsfdsd"));
        request.setEntity(form);

        final Map<String, Object> metricsContext = tokenEndpointMetricsContextSupplier.getMetricsContext(httpRequestContext, request);
        assertThat(metricsContext.size()).isEqualTo(2);
        assertThat(metricsContext.get("grant_type")).isEqualTo(expectedGrantType);
        assertThat(metricsContext.get("scope")).isEqualTo(List.of("payments", "openid"));
    }

    @Test
    void returnsEmptyContextForInvalidRequest() {
        // Valid request with a form body, but does not contain any of the expected fields
        final Request request = new Request().setEntity(new Form());
        final Form form = new Form();
        form.put("client_id", List.of("1232"));
        form.put("something_else", List.of("blah", "blah"));
        form.put("another_thing", List.of("ldfsfdsd"));
        request.setEntity(form);

        assertThat(tokenEndpointMetricsContextSupplier.getMetricsContext(httpRequestContext, request)).isEmpty();
    }

    @Test
    void returnsEmptyContextWhenUnableToAnyDataFromRequest() {
        // Invalid request which is not a form
        assertThat(tokenEndpointMetricsContextSupplier.getMetricsContext(httpRequestContext, new Request())).isEmpty();
    }
}