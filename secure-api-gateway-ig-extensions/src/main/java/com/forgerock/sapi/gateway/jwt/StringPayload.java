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
package com.forgerock.sapi.gateway.jwt;

import static java.util.Objects.requireNonNull;

import org.forgerock.json.jose.jwt.Payload;

/**
 * Class representing a string-based {@link Payload}.
 */
public class StringPayload implements Payload {

    private String payload;

    /**
     * Construct a {@code StringPayload}.
     * @param payload string payload
     */
    public StringPayload(final String payload) {
        this.payload = requireNonNull(payload);
    }

    @Override
    public String build() {
        return payload;
    }

    @Override
    public Payload copy() {
        return new StringPayload(payload);
    }
}
