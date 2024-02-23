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
package com.forgerock.sapi.gateway.common.error;

import static org.forgerock.json.JsonValue.json;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.IOException;

import org.forgerock.http.header.ContentTypeHeader;
import org.forgerock.http.header.GenericHeader;
import org.forgerock.http.header.MalformedHeaderException;
import org.forgerock.http.protocol.Response;
import org.forgerock.http.protocol.Status;
import org.forgerock.json.JsonValue;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import com.forgerock.sapi.gateway.common.rest.ContentTypeFormatterFactory;
import com.forgerock.sapi.gateway.common.rest.HttpMediaTypes;

class OAuthErrorResponseFactoryTest {

    private static final String ERROR_DESCRIPTION = "something bad happened";
    private OAuthErrorResponseFactory oAuthErrorResponseFactory;

    @BeforeEach
    public void beforeEach() {
        oAuthErrorResponseFactory = new OAuthErrorResponseFactory(new ContentTypeFormatterFactory());
    }

    @Test
    void testFailToConstructWhenFormatterFactoryIsNull() {
        assertThrows(NullPointerException.class, () -> new OAuthErrorResponseFactory(null));
    }

    @Test
    void createsInvalidRequestErrorResponse() {
        final Response response = oAuthErrorResponseFactory.invalidRequestErrorResponse(createAcceptHeader(HttpMediaTypes.APPLICATION_JSON), ERROR_DESCRIPTION);
        validateJsonErrorResponse(response, "invalid_request", ERROR_DESCRIPTION);
    }

    @Test
    void createsJsonResponseWhenNoAcceptHeaderSpecified() {
        final Response response = oAuthErrorResponseFactory.invalidRequestErrorResponse(null, ERROR_DESCRIPTION);
        validateJsonErrorResponse(response, "invalid_request", ERROR_DESCRIPTION);
    }

    @Test
    void createsJsonResponseWhenUnsupportedAcceptHeaderSpecified() {
        final Response response = oAuthErrorResponseFactory.invalidRequestErrorResponse(createAcceptHeader("new-media-type"), ERROR_DESCRIPTION);
        validateJsonErrorResponse(response, "invalid_request", ERROR_DESCRIPTION);
    }

    @Test
    void createsInvalidClientErrorResponse() {
        final Response response = oAuthErrorResponseFactory.invalidClientErrorResponse(null, ERROR_DESCRIPTION);
        validateJsonErrorResponse(response, "invalid_client", ERROR_DESCRIPTION);
    }

    @Test
    void createsInvalidGrantErrorResponse() {
        final Response response = oAuthErrorResponseFactory.invalidGrantErrorResponse(null, ERROR_DESCRIPTION);
        validateJsonErrorResponse(response, "invalid_grant", ERROR_DESCRIPTION);
    }

    @Test
    void createsUnauthorizedClientErrorResponse() {
        final Response response = oAuthErrorResponseFactory.unauthorizedClientErrorResponse(null, ERROR_DESCRIPTION);
        validateJsonErrorResponse(response, "unauthorized_client", ERROR_DESCRIPTION);
    }

    @Test
    void createsUnsupportedGrantTypeErrorResponse() {
        final Response response = oAuthErrorResponseFactory.unsupportedGrantTypeErrorResponse(null, ERROR_DESCRIPTION);
        validateJsonErrorResponse(response, "unsupported_grant_type", ERROR_DESCRIPTION);
    }

    @Test
    void createsInvalidScopeErrorResponse() {
        final Response response = oAuthErrorResponseFactory.invalidScopeErrorResponse(null, ERROR_DESCRIPTION);
        validateJsonErrorResponse(response, "invalid_scope", ERROR_DESCRIPTION);
    }

    private static void validateJsonErrorResponse(Response response, String errorType, String errorDescription) {
        assertEquals(Status.BAD_REQUEST, response.getStatus());
        try {
            assertEquals(HttpMediaTypes.APPLICATION_JSON, response.getHeaders().get(ContentTypeHeader.class).getType());
        } catch (MalformedHeaderException e) {
            throw new RuntimeException(e);
        }
        try {
            final JsonValue json = json(response.getEntity().getJson());
            assertEquals(errorType, json.get("error").asString());
            assertEquals(errorDescription, json.get("error_description").asString());
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    private static GenericHeader createAcceptHeader(String mediaType) {
        return new GenericHeader("Accept", mediaType);
    }

}