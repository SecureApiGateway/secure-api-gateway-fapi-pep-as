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
package com.forgerock.sapi.gateway.dcr.request;

import com.forgerock.sapi.gateway.dcr.common.DCRErrorCode;
import com.forgerock.sapi.gateway.dcr.common.exceptions.DCRException;

/**
 * Exception thrown when building a {@code RegistrationRequest} using a {@code Builder}
 */
public class DCRRegistrationRequestBuilderException extends DCRException {
    public DCRRegistrationRequestBuilderException(DCRErrorCode errorCode, String errorDescription) {
        super(errorCode, errorDescription);
    }
}
