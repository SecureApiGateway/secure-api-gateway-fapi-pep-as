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
package com.forgerock.sapi.gateway.common.jwt;

public class AuthorizeRequestParameterNames {
    public final static String  CLIENT_ASSERTION_TYPE = "client_assertion_type";
    public final static String  CLIENT_ASSERTION = "client_assertion";
    public final static String CLIENT_ID = "client_id";
    public final static String REQUEST_URI = "request_uri";
    public final static String REQUEST = "request";
    public final static String SCOPE = "scope";
    public final static String STATE = "state";
    public final static String RESPONSE_TYPE = "response_type";
    public final static String RESPONSE_MODE = "response_mode";
    public final static String REDIRECT_URI = "redirect_uri";
    public final static String NONCE = "nonce";

    public final static String CODE_CHALLENGE = "code_challenge";
    public final static String CODE_CHALLENGE_METHOD = "code_challenge_method";
}
