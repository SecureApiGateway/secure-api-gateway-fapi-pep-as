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

import org.forgerock.openig.fapi.dcr.common.ErrorCode;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class ContentTypeFormatterHtmlTest {

    private ContentTypeFormatterHtml formatter;
    @BeforeEach
    void setUp() {
        formatter = new ContentTypeFormatterHtml();
    }

    @Test
    void success_getFormattedResponse() {
        // Given
        LinkedHashMap<String, String> errorMap = new LinkedHashMap<>();
        errorMap.put("error_code", ErrorCode.INVALID_CLIENT_METADATA.getCode());
        errorMap.put("error_description", "registration request must hold software_statement assert");
        // When
        String entity = formatter.getFormattedResponse(errorMap);

        // Then
        assertThat(entity).isEqualTo("<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">" +
                "<title>Error Response</title><meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">" +
                "</head><body><p><b>error_code:</b> invalid_client_metadata</p><p><b>error_description:</b> " +
                "registration request must hold software_statement assert</p></body></html>");
    }

    @Test
    void successEmptyMap_getFormattedResponse() {
        // Given
        LinkedHashMap<String, String> errorMap = new LinkedHashMap<>();
        // When
        String entity = formatter.getFormattedResponse(errorMap);

        // Then
        assertThat(entity).isEqualTo("<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">" +
                "<title>Error Response</title><meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">" +
                "</head><body></body></html>");
    }

    @Test
    void successNullMap_getFormattedResponse() {
        // Given
        LinkedHashMap<String, String> errorMap = new LinkedHashMap<>();
        // When
        String entity = formatter.getFormattedResponse(null);

        // Then
        assertThat(entity).isEqualTo("<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">" +
                "<title>Error Response</title><meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">" +
                "</head><body></body></html>");
    }
}