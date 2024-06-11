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
package com.forgerock.sapi.gateway.fapi;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;

import java.util.UUID;

import org.forgerock.http.header.GenericHeader;
import org.forgerock.http.protocol.Request;
import org.junit.jupiter.api.Test;

class FapiUtilsTest {
    @Test
    void getFapiInteractionId() {
        assertFalse(FapiUtils.getFapiInteractionId(new Request()).isPresent(), "No x-fapi-interaction-id should be found");

        final String fapiInteractionId = UUID.randomUUID().toString();
        final Request requestWithFapiInteractionIdHeader = new Request().addHeaders(
                new GenericHeader("x-fapi-interaction-id", fapiInteractionId));
        assertEquals(fapiInteractionId, FapiUtils.getFapiInteractionId(requestWithFapiInteractionIdHeader).get());
    }
}
