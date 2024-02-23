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
package com.forgerock.sapi.gateway.dcr.common;

import static org.assertj.core.api.AssertionsForClassTypes.assertThat;

import java.io.IOException;
import java.util.List;
import java.util.Map;

import org.forgerock.http.protocol.Response;
import org.forgerock.http.protocol.Status;
import org.junit.jupiter.api.Test;

import com.forgerock.sapi.gateway.common.rest.ContentTypeFormatterFactory;
import com.forgerock.sapi.gateway.common.rest.ContentTypeNegotiator;
import com.forgerock.sapi.gateway.common.rest.HttpMediaTypes;

class ResponseFactoryTest {

    @Test
    void success_NoAcceptHeaders_getResponse() throws IOException {
        // Given
        ContentTypeFormatterFactory contentTypeFormatterFactory = new ContentTypeFormatterFactory();
        ResponseFactory responseFactory = new ResponseFactory(new ContentTypeNegotiator(contentTypeFormatterFactory.getSupportedContentTypes()), contentTypeFormatterFactory );
        // When
        Response response = responseFactory.getResponse(List.of(), Status.BAD_REQUEST, Map.of("key", "value"));
        // Then
        assertThat(response).isNotNull();
        assertThat(response.getStatus()).isEqualTo(Status.BAD_REQUEST);
        assertThat(response.getHeaders().get("Content-Type").getFirstValue()).isEqualTo("application/json");
        assertThat(response.getEntity().getString()).contains("\"key\":\"value\"");
    }

    @Test
    void success_HTML_getResponse() throws IOException {
        // Given
        ContentTypeFormatterFactory contentTypeFormatterFactory = new ContentTypeFormatterFactory();
        ResponseFactory responseFactory = new ResponseFactory(new ContentTypeNegotiator(contentTypeFormatterFactory.getSupportedContentTypes()), contentTypeFormatterFactory );
        // When
        Response response = responseFactory.getResponse(List.of(HttpMediaTypes.TEXT_HTML), Status.BAD_REQUEST, Map.of("key", "value"));
        // Then
        assertThat(response).isNotNull();
        assertThat(response.getStatus()).isEqualTo(Status.BAD_REQUEST);
        assertThat(response.getHeaders().get("Content-Type").getFirstValue()).isEqualTo(HttpMediaTypes.TEXT_HTML);
        assertThat(response.getEntity().getString()).contains("<p><b>key:</b> value</p>");
    }

    @Test
    void success_TXT_getResponse() throws IOException {
        // Given
        ContentTypeFormatterFactory contentTypeFormatterFactory = new ContentTypeFormatterFactory();
        ResponseFactory responseFactory = new ResponseFactory(new ContentTypeNegotiator(contentTypeFormatterFactory.getSupportedContentTypes()), contentTypeFormatterFactory );
        // When
        Response response = responseFactory.getResponse(List.of(HttpMediaTypes.APPLICATION_TEXT), Status.BAD_REQUEST, Map.of("key", "value"));
        // Then
        assertThat(response).isNotNull();
        assertThat(response.getStatus()).isEqualTo(Status.BAD_REQUEST);
        assertThat(response.getHeaders().get("Content-Type").getFirstValue()).isEqualTo(HttpMediaTypes.APPLICATION_TEXT);
        assertThat(response.getEntity().getString()).contains("key: value");
    }

    @Test
    void failNullAcceptHeaderTypes_getResponse() {
        // Given
        ContentTypeFormatterFactory contentTypeFormatterFactory = new ContentTypeFormatterFactory();
        ResponseFactory responseFactory = new ResponseFactory(new ContentTypeNegotiator(contentTypeFormatterFactory.getSupportedContentTypes()), contentTypeFormatterFactory );
        // When
        Response response = responseFactory.getResponse(null, Status.BAD_REQUEST, Map.of("key", "value"));
        // Then
        assertThat(response).isNotNull();
    }
}