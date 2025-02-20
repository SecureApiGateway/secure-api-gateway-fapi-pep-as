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

import java.util.Map;
import java.util.Optional;

import org.forgerock.services.context.AttributesContext;
import org.forgerock.services.context.Context;

/**
 * Utility methods for working with {@link Context} objects
 */
public class ContextUtils {

    public static final String REGISTRATION_REQUEST_KEY = "registrationRequest";

    private ContextUtils() {
    }

    /**
     * Retrieves an attribute from the Context and returns it as the specified type.
     * A runtime exception is thrown if the attribute does not exist or is not the expected type.
     *
     * @param context       Context to get the attribute from
     * @param attributeName String name of the attribute
     * @param clazz         Class to cast the attribute value as
     * @param <T>           type represented by the clazz arg
     * @return the attribute value cast as type
     */
    public static <T> T getRequiredAttributeAsType(Context context, String attributeName, Class<T> clazz) {
        return getAttributeAsType(context, attributeName, clazz).orElseThrow(
                () -> new IllegalStateException("Required attribute: \"" + attributeName + "\" not found in context"));
    }

    /**
     * Retrieves an attribute from the Context and returns it as the specified type.
     * A runtime exception is thrown if the attribute is not the expected type.
     *
     * @param context       Context to get the attribute from
     * @param attributeName String name of the attribute
     * @param clazz         Class to cast the attribute value as
     * @param <T>           type represented by the clazz arg
     * @return Optional containing either the attribute value cast as type T, or an empty Optional if the attribute does not exist
     */
    public static <T> Optional<T> getAttributeAsType(Context context, String attributeName, Class<T> clazz) {
        final Map<String, Object> attributes = context.asContext(AttributesContext.class).getAttributes();
        final Object attribute = attributes.get(attributeName);
        if (attribute == null) {
            return Optional.empty();
        }
        if (!clazz.isInstance(attribute)) {
            throw new IllegalStateException("Attribute " + "\"" + attributeName + "\" expected to be of type "
                    + clazz.getName() + " but was " + attribute.getClass().getName());
        }
        return Optional.of(clazz.cast(attribute));
    }
}
