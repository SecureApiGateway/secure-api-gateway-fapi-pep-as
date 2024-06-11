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

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import org.forgerock.http.header.ContentTypeHeader;
import org.forgerock.http.protocol.Request;
import org.forgerock.http.protocol.Response;
import org.forgerock.http.protocol.Status;
import org.forgerock.util.Reject;

import com.forgerock.sapi.gateway.common.rest.ContentTypeFormatter;
import com.forgerock.sapi.gateway.common.rest.ContentTypeFormatterFactory;
import com.forgerock.sapi.gateway.common.rest.ContentTypeNegotiator;
import com.forgerock.sapi.gateway.fapi.FapiUtils;

public class ResponseFactory {
    private final ContentTypeNegotiator contentTypeNegotiator;
    private final ContentTypeFormatterFactory contentTypeFormatterFactory;

    public ResponseFactory(ContentTypeNegotiator contentTypeNegotiator,
            ContentTypeFormatterFactory contentTypeFormatterFactory) {
        Reject.ifNull(contentTypeNegotiator, "contentTypeNegotiator must not be null");
        Reject.ifNull(contentTypeFormatterFactory, "contentTypeFormatter must not be null");
        this.contentTypeNegotiator = contentTypeNegotiator;
        this.contentTypeFormatterFactory = contentTypeFormatterFactory;
    }

    public Response getResponse(List<String> acceptValues, Status status, Map<String, String> errorFields) {
        String bestContentType = contentTypeNegotiator.getBestContentType(acceptValues);
        ContentTypeFormatter formatter = this.contentTypeFormatterFactory.getFormatter(bestContentType);
        String entityBody = formatter.getFormattedResponse(errorFields);
        ContentTypeHeader contentTypeHeader = ContentTypeHeader.valueOf(bestContentType);

        return new Response(status).setEntity(entityBody).addHeaders(contentTypeHeader);
    }

    public Response getInternalServerErrorResponse(Request request, List<String> acceptValues) {
        Map<String, String> errorFields = new LinkedHashMap<>();
        errorFields.put("error", "Server unable to process request");
        final Optional<String> fapiInteractionId = FapiUtils.getFapiInteractionId(request);
        if (fapiInteractionId.isPresent()) {
            errorFields.put("trace_id", fapiInteractionId.get());
        }
        return getResponse(acceptValues, Status.INTERNAL_SERVER_ERROR, errorFields);
    }
}
