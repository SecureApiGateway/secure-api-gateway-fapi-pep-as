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
package com.forgerock.sapi.gateway.dcr.common.exceptions;

import org.forgerock.util.Reject;

import com.forgerock.sapi.gateway.dcr.common.DCRErrorCode;

/**
 * Exception for modelling DCR Validation Errors.
 *
 * This exception contains errorCode and errorDescription fields which can be used to produce an error response which adheres
 * to OAuth 2.0 Dynamic Client Registration Protocol spec: https://www.rfc-editor.org/rfc/rfc7591#section-3.2.2
 */
public class ValidationException extends RuntimeException {


    private final DCRErrorCode errorCode;
    private final String errorDescription;

    public ValidationException(DCRErrorCode errorCode, String errorMessage) {
        this(errorCode, errorMessage, null);
    }

    public ValidationException(DCRErrorCode errorCode, String errorMessage, Throwable cause) {
        super((errorCode != null ? errorCode.getCode() : "") + " " + errorMessage, cause);
        this.errorCode = Reject.checkNotNull(errorCode, "errorCode must be supplied");
        this.errorDescription = Reject.checkNotBlank(errorMessage, "errorMessage must be supplied");
    }

    public DCRErrorCode getErrorCode() {
        return errorCode;
    }

    public String getErrorDescription() {
        return errorDescription;
    }
}
