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
package com.forgerock.sapi.gateway.util;

import static com.forgerock.sapi.gateway.util.ContextUtils.getAttributeAsType;
import static com.forgerock.sapi.gateway.util.ContextUtils.getRequiredAttributeAsType;
import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;

import java.util.Map;
import java.util.Optional;
import java.util.UUID;

import org.forgerock.openig.fapi.apiclient.ApiClient;
import org.forgerock.services.context.AttributesContext;
import org.forgerock.services.context.RootContext;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

class ContextUtilsTest {

    @Nested
    class GetAttributeAsTypeTest {
        @Test
        void failToExtractAttributeIfNoAttributesContext() {
            final IllegalArgumentException ex = assertThrows(IllegalArgumentException.class,
                    () -> getAttributeAsType(new RootContext(), "something", String.class));
            assertEquals("No context of type org.forgerock.services.context.AttributesContext found.",
                    ex.getMessage());
        }

        @Test
        void returnsEmptyOptionsIfAttributeDoesNotExist() {
            final Map<String, Object> attributes = Map.of("attr1", 1L,
                                                         "attr2", "value2");

            final AttributesContext attributesContext = buildAttributesContext(attributes);
            assertThat(getAttributeAsType(attributesContext, "clientId", String.class)).isEmpty();
        }

        @Test
        void failToExtractAttributeIfTypeDoesNotMatchExpected() {
            final Map<String, Object> attributes = Map.of("clientId", 1L,
                    "attr2", "value2");
            final IllegalStateException ex = assertThrows(IllegalStateException.class,
                    () -> getAttributeAsType(buildAttributesContext(attributes), "clientId", String.class));

            assertEquals("Attribute \"clientId\" expected to be of type java.lang.String but was java.lang.Long", ex.getMessage());
        }

        @Test
        void extractAttributeFromContext() {
            final Map<String, Object> attributes = Map.of("clientId", UUID.randomUUID().toString(),
                                                          "httpCode", 200,
                                                          "ApiClient", mock(ApiClient.class));

            final AttributesContext attributesContext = buildAttributesContext(attributes);
            for (final Map.Entry<String, Object> entry : attributes.entrySet()) {
                final Object expectedValue = entry.getValue();
                final Optional optionalValue = getAttributeAsType(attributesContext, entry.getKey(), expectedValue.getClass());
                assertThat(optionalValue).isPresent().get().isSameAs(expectedValue);
            }
        }
    }

    @Nested
    class GetRequiredAttributeAsTypeTest {
        @Test
        void extractAttributeFromContext() {
            final Map<String, Object> attributes = Map.of("clientId", UUID.randomUUID().toString(),
                                                          "httpCode", 200,
                                                          "ApiClient", mock(ApiClient.class));

            final AttributesContext attributesContext = buildAttributesContext(attributes);
            for (final Map.Entry<String, Object> entry : attributes.entrySet()) {
                final Object expectedValue = entry.getValue();
                final Object actualValue = getRequiredAttributeAsType(attributesContext, entry.getKey(), expectedValue.getClass());
                assertThat(actualValue).isSameAs(expectedValue);
            }
        }

        @Test
        void failsIfAttributeDoesNotExist() {
            final Map<String, Object> attributes = Map.of("attr1", 1L,
                    "attr2", "value2");

            final AttributesContext attributesContext = buildAttributesContext(attributes);
            final IllegalStateException ex = assertThrows(IllegalStateException.class,
                    () -> getRequiredAttributeAsType(attributesContext, "clientId", String.class));
            assertThat(ex.getMessage()).isEqualTo("Required attribute: \"clientId\" not found in context");
        }
    }

    private static AttributesContext buildAttributesContext(Map<String, Object> attributes) {
        final AttributesContext attributesContext = new AttributesContext(new RootContext());
        attributesContext.getAttributes().putAll(attributes);
        return attributesContext;
    }

}