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

import java.util.List;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class ContentTypeNegotiatorTest {

    private ContentTypeNegotiator negotiator;

    @BeforeEach
    void setUp() {
         List<String> supportedContentTypes = List.of("application/json", "text/html");
        negotiator = new ContentTypeNegotiator(supportedContentTypes);
    }

    @AfterEach
    void tearDown() {
    }

    @Test
    void successFirst_getBestContentType() {
        List<String> acceptHeaderValues = List.of("text/html, application/xhtml+xml, " +
                "application/xml;q=0.9, */*;q=0.8");
        String best = negotiator.getBestContentType(acceptHeaderValues);

        assertThat(best).isEqualTo("text/html");
    }

    @Test
    void successWildcardMatch_getBestContentType() {
        List<String> acceptHeaderValues = List.of("application/xhtml+xml, application/xml;q=0.9, */*;q=0.8");
        String best = negotiator.getBestContentType(acceptHeaderValues);

        assertThat(best).isEqualTo("application/json");
    }

    @Test
    void successLowQMatch_getBestContentType() {
        negotiator = new ContentTypeNegotiator(List.of("application/json", "application/xml"));
        List<String> acceptHeaderValues = List.of("application/xhtml+xml, application/xml;q=0.9, " +
                "application/text;q=0.9, */*;q=0.8");
        String best = negotiator.getBestContentType(acceptHeaderValues);

        assertThat(best).isEqualTo("application/xml");
    }

    @Test
    void successMultipleLowQMatch_getBestContentType() {
        negotiator = new ContentTypeNegotiator(List.of("application/json", "application/xml"));
        List<String> acceptHeaderValues = List.of("application/xhtml+xml, application/text;q=0.9, " +
                "application/xml;q=0.9, */*;q=0.8");
        String best = negotiator.getBestContentType(acceptHeaderValues);

        assertThat(best).isEqualTo("application/xml");
    }

    @Test
    void successNoAcceptHeaderValues_getBestContentType() {
        negotiator = new ContentTypeNegotiator(List.of("application/json", "application/xml"));
        List<String> acceptHeaderValues = List.of();
        String best = negotiator.getBestContentType(acceptHeaderValues);

        assertThat(best).isEqualTo("application/json");
    }

    @Test
    void successNullAcceptHeaderValues_getBestContentType() {
        negotiator = new ContentTypeNegotiator(List.of("application/json", "application/xml"));
        String best = negotiator.getBestContentType(null);

        assertThat(best).isEqualTo("application/json");
    }
}