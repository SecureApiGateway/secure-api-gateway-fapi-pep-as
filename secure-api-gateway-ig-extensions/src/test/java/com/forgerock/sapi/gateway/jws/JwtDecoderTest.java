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
package com.forgerock.sapi.gateway.jws;

import static org.assertj.core.api.AssertionsForClassTypes.assertThat;
import static org.assertj.core.api.AssertionsForClassTypes.catchThrowableOfType;

import org.forgerock.json.jose.jws.SignedJwt;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import com.forgerock.sapi.gateway.common.jwt.JwtException;
import com.forgerock.sapi.gateway.dcr.sigvalidation.DCRTestHelpers;

class JwtDecoderTest {

    private static JwtDecoder jwtDecoder;

    @BeforeAll
    public static void setup(){
        jwtDecoder = new JwtDecoder();
    }

    @Test
    void success_getSignedJwt() {
        // Given

        // WHen
        SignedJwt signedJwt = null;
        try {
            signedJwt = jwtDecoder.getSignedJwt(DCRTestHelpers.VALID_SSA_FROM_IG);
        } catch (com.forgerock.sapi.gateway.common.jwt.JwtException e) {
            throw new RuntimeException(e);
        }
        // Then
        assertThat(signedJwt).isNotNull();
    }

    @Test
    void failsInvalidb64EncodedString_getSignedJwt() {
        // Given

        // WHen
        JwtException jwtReconstructionException = catchThrowableOfType(
                () ->jwtDecoder.getSignedJwt("invalidjwtstring"),  JwtException.class);
        // Then
        assertThat(jwtReconstructionException).isNotNull();
    }
  
}