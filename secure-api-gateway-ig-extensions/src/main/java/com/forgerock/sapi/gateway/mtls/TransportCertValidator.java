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
package com.forgerock.sapi.gateway.mtls;

import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.stream.Stream;

import org.forgerock.json.jose.jwk.JWKSet;
import org.forgerock.secrets.jwkset.JwkSetSecretStore;
import org.forgerock.secrets.keys.CertificateVerificationKey;
import org.forgerock.util.promise.Promise;

/**
 * Validator which tests if a certificate belongs to a JWKSet and may be used for MTLS purposes.
 */
public interface TransportCertValidator {

    /**
     * Validate the {@code clientCertificate} against the JWKS obtained from the {@code jwkSetSecretStore}. Note that
     * if not keys are valid then the resulting stream will be empty.
     *
     * @param clientCertificate {@link X509Certificate} MTLS certificate of the client to validate
     * @param jwkSetSecretStore {@link JwkSetSecretStore} containing the client's keys
     * @return a {@link Promise} carrying a {@link CertificateException} if the certificate is not valid (as per the
     *         original API)
     */
    Promise<Void, CertificateException> validate(X509Certificate clientCertificate,
                                                 JwkSetSecretStore jwkSetSecretStore);
}
