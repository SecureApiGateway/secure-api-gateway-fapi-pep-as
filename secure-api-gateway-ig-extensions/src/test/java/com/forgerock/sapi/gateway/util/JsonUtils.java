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
package com.forgerock.sapi.gateway.util;

import static org.forgerock.json.JsonValue.json;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.forgerock.json.JsonValue;

/**
 * Utils for working with json in tests
 */
public class JsonUtils {

    /**
     * Asserts that JsonValues are equal, delegates to {@link JsonValue#isEqualTo(JsonValue)}.
     * If the values do not match then the {@link JsonValue#diff(JsonValue)} is used to report the differences.
     */
    public static void assertJsonEquals(JsonValue expectedJson, JsonValue actualJson) {
        assertTrue(expectedJson.isEqualTo(json(actualJson)),
                "json does not match expected\njson diff vs expected:" + expectedJson.diff(actualJson));
    }
}
