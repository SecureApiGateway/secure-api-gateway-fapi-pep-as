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
package com.forgerock.sapi.gateway.dcr.common.exceptions;

import java.util.LinkedHashMap;
import java.util.Map;

import org.forgerock.util.Reject;

import com.forgerock.sapi.gateway.dcr.common.DCRErrorCode;

/**
 * An exception thrown during the processing of a Dynamic Client Registration request
 */
public class DCRException extends Exception {
    protected final DCRErrorCode errorCode;
    protected final String errorDescription;
    
    public DCRException(DCRErrorCode errorCode, String errorDescription){
        this(errorCode, errorDescription, null);
    }

    public DCRException(DCRErrorCode errorCode, String errorDescription, Throwable cause){
        super("errorCode: '" + errorCode.getCode() + "', errorDescription: '" + errorDescription + "'", cause);
        Reject.checkNotNull(errorCode, "errorCode must be supplied");
        Reject.checkNotBlank(errorDescription, "errorMessage must be supplied");
        this.errorCode = errorCode;
        this.errorDescription = errorDescription;
    }

    public DCRErrorCode getErrorCode() {
        return errorCode;
    }

    public String getErrorDescription() {
        return errorDescription;
    }

    public Map<String, String> getErrorFields(){
        LinkedHashMap<String, String> fields = new LinkedHashMap<>();
        fields.put("error", errorCode.getCode());
        fields.put("error_description", errorDescription);
        return fields;
    };
}
