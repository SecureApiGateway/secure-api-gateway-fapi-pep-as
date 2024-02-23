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
package com.forgerock.sapi.gateway.common.rest;

import static org.assertj.core.api.AssertionsForClassTypes.assertThat;

import java.util.Map;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import com.forgerock.sapi.gateway.dcr.common.DCRErrorCode;

class ContentTypeFormatterJsonTest {

    private ContentTypeFormatterJson formatter;

    @BeforeEach
    public void setup(){
        formatter = new ContentTypeFormatterJson();
    }

    @Test
    public void success_getFormattedResponse(){
        // Given
        Map<String, String> errorFields = Map.of("error_code", DCRErrorCode.INVALID_CLIENT_METADATA.getCode());
        // When
        String json = formatter.getFormattedResponse(errorFields);
        // Then
        assertThat(json).isEqualTo("{\"error_code\":\"invalid_client_metadata\"}");
    }

    @Test
    public void successEmptyErrorFields_getFormattedResponse(){
        // Given
        Map<String, String> errorFields = Map.of();
        // When
        String json = formatter.getFormattedResponse(errorFields);
        // Then
        assertThat(json).isEqualTo("{}");
    }

    @Test
    public void failNullErrorFields_getFormattedResponse(){
        // Given
        // When
        String json = formatter.getFormattedResponse(null);
        // Then
        assertThat(json).isEqualTo("{}");
    }
}