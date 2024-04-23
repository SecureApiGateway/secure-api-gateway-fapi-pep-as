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
package com.forgerock.sapi.gateway.dcr.sigvalidation;

import static org.assertj.core.api.AssertionsForClassTypes.assertThat;
import static org.assertj.core.api.AssertionsForClassTypes.catchThrowableOfType;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.reset;
import static org.mockito.Mockito.when;

import java.net.URI;

import org.forgerock.json.jose.exceptions.FailedToLoadJWKException;
import org.forgerock.json.jose.jwk.JWKSet;
import org.forgerock.util.promise.Promise;
import org.forgerock.util.promise.Promises;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import com.forgerock.sapi.gateway.dcr.models.RegistrationRequest;
import com.forgerock.sapi.gateway.dcr.models.SoftwareStatement;
import com.forgerock.sapi.gateway.jwks.JwkSetService;

class JwksSupplierJwksUriTest {

    private final static JwkSetService jwkSetService = mock(JwkSetService.class);
    private final RegistrationRequest registrationRequest = mock(RegistrationRequest.class);
    private final SoftwareStatement softwareStatement = mock(SoftwareStatement.class);
    private JwksSupplierJwksUri jwksUriSignatureValidator;

    @BeforeEach
    void setUp() {
        jwksUriSignatureValidator = new JwksSupplierJwksUri(jwkSetService);
        when(registrationRequest.getSoftwareStatement()).thenReturn(softwareStatement);
        when(softwareStatement.hasJwksUri()).thenReturn(true);
    }

    @AfterEach
    void tearDown() {
        reset(jwkSetService, registrationRequest, softwareStatement);
    }

    @Test
    void failsCantGetJwksSetFromUri_getJwks() {
        // Given
        final URI jwksUri = URI.create("https://jwks_uri.com");
        when(softwareStatement.getJwksUri()).thenReturn(jwksUri);
        when(jwkSetService.getJwkSet(jwksUri)).thenReturn(
                Promises.newExceptionPromise(new FailedToLoadJWKException("Couldn't load JWKS")));

        // When
        Promise<JWKSet, FailedToLoadJWKException> promise =
                jwksUriSignatureValidator.getJWKSet(registrationRequest);

        FailedToLoadJWKException exception = catchThrowableOfType(promise::getOrThrow,
                FailedToLoadJWKException.class);

        // Then
        assertThat(exception).isNotNull();
    }


    @Test
    void success_getJWKSet() throws InterruptedException, FailedToLoadJWKException {
        // Given
        final URI jwksUri = URI.create("https://jwks_uri.com");
        when(softwareStatement.getJwksUri()).thenReturn(jwksUri);
        JWKSet jwks = new JWKSet();
        when(jwkSetService.getJwkSet(jwksUri)).thenReturn(Promises.newResultPromise(jwks));

        // When
        Promise<JWKSet, FailedToLoadJWKException> promise =
                jwksUriSignatureValidator.getJWKSet(registrationRequest);
        JWKSet jwkSet = promise.getOrThrow();

        // Then
        assertThat(jwkSet).isEqualTo(jwkSet);
    }
}