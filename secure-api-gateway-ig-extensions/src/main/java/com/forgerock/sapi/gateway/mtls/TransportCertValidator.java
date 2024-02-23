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
package com.forgerock.sapi.gateway.mtls;

import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import org.forgerock.json.jose.jwk.JWKSet;

/**
 * Validator which tests if a certificate belongs to a JWKSet and may be used for MTLS purposes.
 */
public interface TransportCertValidator {

    /**
     * validate the certificate
     *
     * @param certificate X509Certificate MTLS certificate of the client to validate
     * @param jwkSet JWKSet containing the client's keys
     * @throws CertificateException if the certificate is not a valid MTLS certificate for this client.
     */
    void validate(X509Certificate certificate, JWKSet jwkSet) throws CertificateException;

}
