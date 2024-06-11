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

/**
 * Dynamic Client Registration (/register) endpoint error codes, as specified by spec:
 * <a href="https://www.rfc-editor.org/rfc/rfc7591#section-3.2.2">OAuth 2.0 Dynamic Client Registration Protocol</a>
 */
public enum DCRErrorCode {
    INVALID_REDIRECT_URI("invalid_redirect_uri"),
    INVALID_CLIENT_METADATA("invalid_client_metadata"),
    INVALID_SOFTWARE_STATEMENT("invalid_software_statement"),
    UNAPPROVED_SOFTWARE_STATEMENT("unapproved_software_statement");

    private final String code;

    DCRErrorCode(String code) {
        this.code = code;
    }

    public String getCode() {
        return code;
    }
}
