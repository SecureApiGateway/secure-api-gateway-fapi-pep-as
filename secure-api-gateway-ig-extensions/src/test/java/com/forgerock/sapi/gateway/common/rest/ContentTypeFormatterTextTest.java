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
package com.forgerock.sapi.gateway.common.rest;

import static org.assertj.core.api.AssertionsForClassTypes.assertThat;

import java.util.LinkedHashMap;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;


class ContentTypeFormatterTextTest {

    private ContentTypeFormatterText formatter;

    @BeforeEach
    void setUp() {
        formatter = new ContentTypeFormatterText();
    }

    @Test
    void success_getFormattedResponse() {
        // Given
        LinkedHashMap<String, String> fields = new LinkedHashMap<>();
        fields.put("error_code", "code red!");
        fields.put("error_description", "everything is broken");

        // When
        String formattedError = formatter.getFormattedResponse(fields);

        // Then
        assertThat(formattedError).isEqualTo("error_code: code red!\nerror_description: everything " +
                "is broken\n");
    }
}