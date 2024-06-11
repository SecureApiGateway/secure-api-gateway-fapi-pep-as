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
package com.forgerock.sapi.gateway.jwks;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.argThat;

import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.util.List;

import org.forgerock.json.jose.exceptions.FailedToLoadJWKException;
import org.forgerock.json.jose.jwk.JWK;
import org.forgerock.json.jose.jwk.JWKSet;
import org.forgerock.json.jose.jwk.JWKSetParser;
import org.forgerock.json.jose.jwk.RsaJWK;
import org.forgerock.util.promise.Promises;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
public class RestJwkSetServiceTest {

    @Mock
    private JWKSetParser jwkSetParser;

    public static JWK createJWK(String keyId) {
        return RsaJWK.builder("modulusValue", "exponentValue").keyId(keyId).build();
    }

    private void mockJwkSet(JWK expectedJwk, URI jwkSetUri) {
        final URL urlMatcher = argThat(url -> {
            try {
                return url.toURI().equals(jwkSetUri);
            } catch (URISyntaxException e) {
                throw new RuntimeException(e);
            }
        });
        Mockito.when(jwkSetParser.jwkSetAsync(urlMatcher))
               .thenReturn(Promises.newResultPromise(new JWKSet(List.of(createJWK("dfsd"), createJWK("fssd"),
                                                                expectedJwk, createJWK("fdssffff")))));
    }

    private void mockJwkSet(URI jwkSetUri) {
        mockJwkSet(createJWK("anotherTestJwk"), jwkSetUri);
    }

    @Test
    void shouldFindKidInJWKSet() throws Exception {
        final String kid1 = "kid1";
        final JWK jwk = createJWK(kid1);
        final URI jwkSetUri = URI.create("http://abc");
        mockJwkSet(jwk, jwkSetUri);
        final RestJwkSetService restJwkSetService = new RestJwkSetService(jwkSetParser);
        assertEquals(jwk.getKeyId(), restJwkSetService.getJwk(jwkSetUri, kid1).get().getKeyId());
    }

    @Test
    void shouldReturnNullIfKidNotInJWKSet() {
        final URI jwkSetUri = URI.create("http://abc");
        mockJwkSet(jwkSetUri);
        final RestJwkSetService restJwkSetService = new RestJwkSetService(jwkSetParser);
        final FailedToLoadJWKException failedToLoadJWKException = assertThrows(FailedToLoadJWKException.class,
                () -> restJwkSetService.getJwk(jwkSetUri, "kid2").getOrThrow());
        assertEquals("Failed to find keyId: kid2 in JWKSet", failedToLoadJWKException.getMessage());
    }
}