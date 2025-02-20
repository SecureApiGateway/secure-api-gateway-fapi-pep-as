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
import java.security.interfaces.RSAPublicKey;
import java.util.List;

import org.forgerock.json.jose.jwk.JWK;
import org.forgerock.json.jose.jwk.JWKSet;
import org.forgerock.openig.heap.GenericHeaplet;
import org.forgerock.openig.heap.HeapException;
import org.forgerock.util.Reject;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.RSAKey;

/**
 * Certificate validation is achieved by transforming the incoming client certificate into a JWK and then testing if the
 * JWK exists in the supplied JWKSet for the client.
 *
 * As we do not have a keyId (kid) for the certificate, then JWK equality is determined by comparing the x5c[0] values.
 * The x5c[0] represents the base64 encoded DER PKIX certificate value. The first item in the x5c array must be the
 * certificate, therefore we only check this entry and not the full chain.
 *
 * Spec for JWK.x5c field: https://www.rfc-editor.org/rfc/rfc7517#section-4.7
 *
 * Additionally, when a matching JWK is found in the JWKSet then the JWK.use field may be tested to see if it matches
 * the configured validKeyUse value. If this configuration is omitted, then use checking is not done.
 * For the Open Banking use case, the JWK.use value is expected to be "tls" for a cert that is used for MTLS purposes,
 * NOTE: that the "tls" use value is a custom value defined by Open Banking.
 */
public class DefaultTransportCertValidator implements TransportCertValidator {

    /**
     * Optionally validate that the JWK entry has a "use" value that matches this value.
     *
     * If this is configured as null, then checking of the "use" value will be skipped.
     */
    private final String validKeyUse;

    public DefaultTransportCertValidator() {
        this(null);
    }

    public DefaultTransportCertValidator(String validKeyUse) {
        this.validKeyUse = validKeyUse;
    }

    @Override
    public void validate(X509Certificate certificate, JWKSet jwkSet) throws CertificateException {
        Reject.ifNull(certificate, "certificate must be supplied");
        Reject.ifNull(jwkSet, "jwkSet must be supplied");
        certificate.checkValidity();
        try {
            final String x5cForClientCert = getX5cForClientCert(certificate);
            if (!tlsClientCertExistsInJwkSet(jwkSet, x5cForClientCert)) {
                throw new CertificateException("Failed to find JWK entry in provided JWKSet which matches the X509 cert");
            }
        } catch (JOSEException e) {
            throw new CertificateException("Failed to validate transport cert due to exception", e);
        }
    }

    /**
     * Converts the X509 certificate into x5c format (see https://www.rfc-editor.org/rfc/rfc7517#section-4.7) so
     * that it can be compared to the x5c values present for the JWK objects in the JWKS
     *
     * @param certificate X509Certificate to get the x5c value for
     * @return String representing the x5c value of the cert
     * @throws JOSEException if the certificate cannot be converted into a JWK
     */
    private String getX5cForClientCert(X509Certificate certificate) throws JOSEException {
        if (certificate.getPublicKey() instanceof RSAPublicKey) {
            return RSAKey.parse(certificate).getX509CertChain().get(0).toString();
        }
        throw new IllegalStateException("Unsupported certificate type: " + certificate.getClass());
    }

    /**
     * Check if the client's transport cert exists in the JWKSet by comparing JWK.x5c values with the supplied clientCertX5c
     *
     * If the cert does exist, then optionally test the key's use to see if it is valid for use as a transport key.
     *
     * @param jwkSet JWKSet to check
     * @param clientCertX5c String representing the JWK.x5c value we are expecting to match.
     *                      NOTE: we are only testing the client cert portion of the x5c array, the first item in the array
     *                      and not the whole cert chain.
     * @return true if the cert exists in the JWK and has the correct keyUse
     */
    private boolean tlsClientCertExistsInJwkSet(JWKSet jwkSet, String clientCertX5c) {
        for (JWK jwk : jwkSet.getJWKsAsList()) {
            final List<String> x509Chain = jwk.getX509Chain();
            final String jwkX5c = x509Chain.get(0);
            if (isKeyUseValid(jwk) && clientCertX5c.equals(jwkX5c)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Validates the JWK "use" value.
     *
     * @param jwk the JWK to validate
     * @return If keyUse field is not configured, then this always returns true.
     *         Otherwise, returns whether the JWK.use matches the keyUse field
     */
    private boolean isKeyUseValid(JWK jwk) {
        if (validKeyUse == null) {
            return true;
        }
        return validKeyUse.equals(jwk.getUse());
    }

    /**
     * Heaplet responsible for creating {@link DefaultTransportCertValidator} objects
     *
     * Optional config:
     * - validKeyUse String value to test the JWK.use, this config may be omitted and no use field checking is done.
     *
     * Example config:
     * {
     *       "name": "OBTransportCertValidator",
     *       "type": "TransportCertValidator",
     *       "config": {
     *         "validKeyUse": "tls"
     *       }
     * }
     */
    public static class Heaplet extends GenericHeaplet {

        @Override
        public Object create() throws HeapException {
            final String validKeyUse = config.get("validKeyUse").asString();
            return new DefaultTransportCertValidator(validKeyUse);
        }
    }
}
