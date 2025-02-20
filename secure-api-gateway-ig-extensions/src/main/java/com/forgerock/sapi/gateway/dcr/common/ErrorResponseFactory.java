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
package com.forgerock.sapi.gateway.dcr.common;

import static org.forgerock.json.JsonValue.field;
import static org.forgerock.json.JsonValue.json;
import static org.forgerock.json.JsonValue.object;

import org.forgerock.http.protocol.Response;
import org.forgerock.http.protocol.Status;
import org.forgerock.json.JsonValue;
import org.forgerock.services.context.Context;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.forgerock.sapi.gateway.dcr.common.exceptions.ValidationException;


/**
 * Factory which creates Response objects for DCR error conditions as per:
 * OAuth 2.0 Dynamic Client Registration Protocol spec https://www.rfc-editor.org/rfc/rfc7591#section-3.2.2
 */
public class ErrorResponseFactory {

    private final Logger logger = LoggerFactory.getLogger(getClass());

    public ErrorResponseFactory() {
    }

    public Response errorResponse(Context context, ValidationException validationException) {
        return errorResponse(context, validationException.getErrorCode(), validationException.getErrorDescription());
    }

    public Response errorResponse(Context context, DCRErrorCode errorCode, String errorDescription) {
        final Response response = new Response(Status.BAD_REQUEST);
        final JsonValue errorResponseBody = json(object(field("error", errorCode.getCode()),
                                                        field("error_description", errorDescription)));
        response.setEntity(errorResponseBody);
        logger.warn("DCR Request failed validation, errorResponse: {}", errorResponseBody);
        return response;
    }
}
