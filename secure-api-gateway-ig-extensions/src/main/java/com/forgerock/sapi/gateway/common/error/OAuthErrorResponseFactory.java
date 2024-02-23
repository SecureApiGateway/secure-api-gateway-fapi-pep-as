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

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.forgerock.http.header.ContentTypeHeader;
import org.forgerock.http.protocol.Header;
import org.forgerock.http.protocol.Response;
import org.forgerock.http.protocol.Status;
import org.forgerock.util.Reject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.forgerock.sapi.gateway.common.rest.ContentTypeFormatter;
import com.forgerock.sapi.gateway.common.rest.ContentTypeFormatterFactory;
import com.forgerock.sapi.gateway.common.rest.ContentTypeNegotiator;


/**
 * Factory which creates Response objects for OAuth2 related errors as described in the following specifications:
 * https://www.rfc-editor.org/rfc/rfc6749#section-5.2
 */
public class OAuthErrorResponseFactory {

    private static final String INVALID_REQUEST = "invalid_request";
    private static final String INVALID_CLIENT = "invalid_client";
    private static final String INVALID_GRANT = "invalid_grant";
    private static final String UNAUTHORIZED_CLIENT = "unauthorized_client";
    private static final String UNSUPPORTED_GRANT_TYPE = "unsupported_grant_type";
    private static final String INVALID_SCOPE = "invalid_scope";

    private final Logger logger = LoggerFactory.getLogger(getClass());
    private final ContentTypeFormatterFactory messageFormatterFactory;
    private final ContentTypeNegotiator contentTypeNegotiator;

    public OAuthErrorResponseFactory(ContentTypeFormatterFactory messageFormatterFactory) {
        this.messageFormatterFactory = Reject.checkNotNull(messageFormatterFactory, "messageFormatterFactory must be provided");
        this.contentTypeNegotiator = new ContentTypeNegotiator(messageFormatterFactory.getSupportedContentTypes());
    }

    public Response invalidRequestErrorResponse(Header acceptHeader, String errorDescription) {
        return createErrorResponse(INVALID_REQUEST, acceptHeader, errorDescription);
    }

    public Response invalidClientErrorResponse(Header acceptHeader, String errorDescription) {
        return createErrorResponse(INVALID_CLIENT, acceptHeader, errorDescription);
    }

    public Response invalidGrantErrorResponse(Header acceptHeader, String errorDescription) {
        return createErrorResponse(INVALID_GRANT, acceptHeader, errorDescription);
    }

    public Response unauthorizedClientErrorResponse(Header acceptHeader, String errorDescription) {
        return createErrorResponse(UNAUTHORIZED_CLIENT, acceptHeader, errorDescription);
    }

    public Response unsupportedGrantTypeErrorResponse(Header acceptHeader, String errorDescription){
        return createErrorResponse(UNSUPPORTED_GRANT_TYPE, acceptHeader, errorDescription);
    }

    public Response invalidScopeErrorResponse(Header acceptHeader, String errorDescription) {
        return createErrorResponse(INVALID_SCOPE, acceptHeader, errorDescription);
    }

    private Response createErrorResponse(String errorType, Header acceptHeader, String errorDescription){
        final List<String> acceptHeaderValues = acceptHeader == null ? Collections.emptyList() : acceptHeader.getValues();
        final String bestContentType = contentTypeNegotiator.getBestContentType(acceptHeaderValues);

        final Map<String, String> errorFields = new LinkedHashMap<>();
        errorFields.put("error", errorType);
        errorFields.put("error_description", errorDescription);

        return errorResponse(Status.BAD_REQUEST, errorFields, bestContentType);
    }

    private Response errorResponse(Status httpCode, Map<String, String> errorFields, String contentType) {
        String errorMessage = getErrorMessage(errorFields, contentType);
        logger.info("creating OAuth Error Response, http status: {}, error: {}", httpCode, errorMessage);
        Response response = new Response(httpCode);
        response.setEntity(errorMessage);
        response.addHeaders(new ContentTypeHeader(contentType, Map.of()));
        return response;
    }

    private String getErrorMessage(Map<String, String> errorFields, String contentType) {
        ContentTypeFormatter formatter = messageFormatterFactory.getFormatter(contentType);
        return formatter.getFormattedResponse(errorFields);
    }

}
