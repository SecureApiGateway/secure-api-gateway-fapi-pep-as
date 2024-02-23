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
package com.forgerock.sapi.gateway.am;

import static org.forgerock.json.JsonValue.field;
import static org.forgerock.json.JsonValue.json;
import static org.forgerock.json.JsonValue.object;
import static org.junit.jupiter.api.Assertions.*;

import java.security.SignatureException;
import java.text.ParseException;
import java.util.UUID;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

import org.forgerock.json.JsonValue;
import org.forgerock.json.jose.exceptions.InvalidJwtException;
import org.forgerock.openig.heap.HeapImpl;
import org.forgerock.openig.heap.Name;
import org.forgerock.util.promise.Promise;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import com.forgerock.sapi.gateway.am.JwtReSigner.Heaplet;
import com.forgerock.sapi.gateway.util.CryptoUtils;
import com.nimbusds.jose.crypto.RSASSASigner;

class JwtReSignerTest {

    private final JwtReSignerTestResourceManager jwtReSignerTestResourceManager;
    private final JwtReSigner jwtReSigner;

    public JwtReSignerTest() {
        jwtReSignerTestResourceManager = new JwtReSignerTestResourceManager();
        jwtReSigner = jwtReSignerTestResourceManager.getJwtReSigner();
    }

    @Test
    void jwtReSigned() throws Exception {
        testJwtReSigned(jwtReSigner);
    }

    private void testJwtReSigned(JwtReSigner jwtReSigner) throws InterruptedException, SignatureException, TimeoutException, ParseException {
        final String jti = UUID.randomUUID().toString();
        final Promise<String, SignatureException> reSignPromise = jwtReSigner.reSignJwt(jwtReSignerTestResourceManager.createAmSignedJwt(jti));

        final String reSignedJwt = reSignPromise.getOrThrow(1, TimeUnit.SECONDS);

        jwtReSignerTestResourceManager.validateJwtHasBeenReSigned(jti, reSignedJwt);
    }

    @Test
    void failsWhenJwtStringInvalid() {
        final Promise<String, SignatureException> reSignPromise = jwtReSigner.reSignJwt("not a jwt string");

        final SignatureException signException = assertThrows(SignatureException.class, () -> reSignPromise.getOrThrow(1, TimeUnit.SECONDS));
        assertEquals("Invalid jwtString supplied", signException.getMessage());
        assertInstanceOf(InvalidJwtException.class, signException.getCause());
    }

    @Test
    void failsWhenJwtParamHasNotBeenSignedByAM() throws Exception {
        // Re-signing fails if we cannot verify that the JWT has a valid signature produced by AM.
        final RSASSASigner unknownSigner = new RSASSASigner(CryptoUtils.generateRsaKeyPair().getPrivate());
        final Promise<String, SignatureException> reSignPromise = jwtReSigner.reSignJwt(jwtReSignerTestResourceManager.createSignedJwt(unknownSigner, "kid-123", "jti-123"));

        final SignatureException signException = assertThrows(SignatureException.class, () -> reSignPromise.getOrThrow(1, TimeUnit.SECONDS));
        assertEquals("Unable to re-sign JWT - signature not valid for configured AM signing key", signException.getMessage());
    }


    @Nested
    class HeapletTests {

        @Test
        void testJwtReSignerCreatedByHeaplet() throws Exception {
            final JsonValue config = createJsonConfig();
            final HeapImpl heap = createHeap();

            final JwtReSigner jwtReSigner = (JwtReSigner) new Heaplet().create(Name.of("test"), config, heap);
            testJwtReSigned(jwtReSigner);
        }

        private HeapImpl createHeap() {
            final HeapImpl heap = new HeapImpl(Name.of("test"));
            heap.put("ObSigningSecretsProvider", jwtReSignerTestResourceManager.getObSigningSecretsProvider());
            heap.put("AMSecretsProvider", jwtReSignerTestResourceManager.getAmVerifyingSecretsProvider());
            return heap;
        }

        private JsonValue createJsonConfig() {
            return json(object(field("verificationSecretsProvider", "AMSecretsProvider"),
                    field("verificationSecretId", "value.is.ignored"),
                    field("signingSecretsProvider", "ObSigningSecretsProvider"),
                    field("signingKeyId", jwtReSignerTestResourceManager.getObSigningKeyId()),
                    field("signingKeySecretId", jwtReSignerTestResourceManager.getSigningKeyPurpose().getLabel())));
        }

    }

}