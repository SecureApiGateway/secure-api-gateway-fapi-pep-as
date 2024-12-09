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

import java.util.List;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class ContentTypeFormatterFactoryTest {

    private ContentTypeFormatterFactory formatterFactory;

    @BeforeEach
    void setUp() {
        formatterFactory = new ContentTypeFormatterFactory();
    }

    @Test
    void getSupportedContentTypes() {
        // Given
        // When
        List<String> contentTypes = formatterFactory.getSupportedContentTypes();
        // Then
        assertThat(contentTypes).isNotNull();
        assertThat(contentTypes.isEmpty()).isFalse();
    }

    @Test
    void successHtml_getFormatter() {
        // Given
        String contentType = HttpMediaTypes.TEXT_HTML;
        // When
        ContentTypeFormatter formatter = formatterFactory.getFormatter(contentType);
        // Then
        assertThat(formatter).isNotNull();
        assertThat(formatter).isInstanceOf(ContentTypeFormatterHtml.class);
    }

    @Test
    void successJson_getFormatter(){
        // Given
        String contentType = HttpMediaTypes.APPLICATION_JSON;
        // When
        ContentTypeFormatter formatter = formatterFactory.getFormatter(contentType);
        // Then
        assertThat(formatter).isNotNull();
        assertThat(formatter).isInstanceOf(ContentTypeFormatterJson.class);
    }

    @Test
    void successText_getFormatter(){
        // Given
        String contentType = HttpMediaTypes.APPLICATION_TEXT;
        // When
        ContentTypeFormatter formatter = formatterFactory.getFormatter(contentType);
        // Then
        assertThat(formatter).isNotNull();
        assertThat(formatter).isInstanceOf(ContentTypeFormatterText.class);
    }

    @Test
    void successDefaultIsJson_getFormatter(){
        // Given
        String contentType = "invalid media type";
        // When
        ContentTypeFormatter formatter = formatterFactory.getFormatter(contentType);
        // Then
        assertThat(formatter).isNotNull();
        assertThat(formatter).isInstanceOf(ContentTypeFormatterJson.class);
    }
}