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

import static java.util.Objects.requireNonNull;
import static org.forgerock.json.JsonValueFunctions.optionalOf;
import static org.forgerock.openig.util.JsonValues.purposeOf;
import static org.forgerock.secrets.Purpose.VERIFY_CERTIFICATE;
import static org.forgerock.util.promise.NeverThrowsException.neverThrown;
import static org.forgerock.util.promise.Promises.newExceptionPromise;

import java.security.MessageDigest;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.stream.Stream;

import org.forgerock.json.JsonValue;
import org.forgerock.openig.fapi.jwks.CachingJwkSetService;
import org.forgerock.openig.heap.GenericHeaplet;
import org.forgerock.openig.heap.HeapException;
import org.forgerock.secrets.Purpose;
import org.forgerock.secrets.SecretConstraint;
import org.forgerock.secrets.jwkset.JwkSetSecretStore;
import org.forgerock.secrets.keys.CertificateVerificationKey;
import org.forgerock.secrets.keys.CryptoKey;
import org.forgerock.util.promise.Promise;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Certificate validation is achieved by comparing the incoming {@link X509Certificate client certificate} with
 * those obtained from the client {@link JwkSetSecretStore JWKSet}. That is, we obtain valid certificates for the
 * expected {@code validKeyUse} from the JWKSet and compare the client certificate with these certificates to find
 * match.
 * <p>
 * If no {@code validKeyUse} is supplied, then the default {@link Purpose#VERIFY_CERTIFICATE "verifyCertificate"} label
 * is used. For the Open Banking use case, the {@code JWK.use} value is expected to be
 * {@value org.forgerock.json.jose.jwk.KeyUseConstants#TLS} for a cert that is used for MTLS purposes. This is a custom
 * key use defined by Open Banking.
 */
public class DefaultTransportCertValidator implements TransportCertValidator {

    private static final Logger LOGGER = LoggerFactory.getLogger(DefaultTransportCertValidator.class);

    private final Purpose<CertificateVerificationKey> transportCertPurpose;

    public DefaultTransportCertValidator(final Purpose<CertificateVerificationKey> transportCertPurpose) {
        this.transportCertPurpose = requireNonNull(transportCertPurpose);
    }

    public Promise<Void, CertificateException> validate(X509Certificate clientCertificate,
                                                        JwkSetSecretStore jwkSetSecretStore) {
        requireNonNull(clientCertificate, "certificate must be supplied");
        requireNonNull(jwkSetSecretStore, "jwkSetSecretStore must be supplied");
        try {
            clientCertificate.checkValidity();
        } catch (CertificateException certException) {
            return newExceptionPromise(certException);
        }
        Purpose<CertificateVerificationKey> certConstrainedPurpose =
                transportCertPurpose.withConstraints(matchesX509Cert(clientCertificate));
        return jwkSetSecretStore.getValid(certConstrainedPurpose)
                .then(this::keysPresentInRegisteredCerts, neverThrown());
    }

    private static SecretConstraint<CryptoKey> matchesX509Cert(final X509Certificate transportCert) {
        // Note that this emulates the real way in which an X.509 cert will be validated via a JwkSetSecretStore
        return secret -> {
            try {
                transportCert.checkValidity();
            } catch (CertificateExpiredException | CertificateNotYetValidException certificateException) {
                LOGGER.trace("Client certificate is not valid", certificateException);
                return false;
            }
            return secret.getCertificate(X509Certificate.class)
                         .filter(x509Cert -> x509CertsEqual(x509Cert, transportCert))
                         .isPresent();
        };
    }

    private static boolean x509CertsEqual(final X509Certificate cert1, final X509Certificate cert2) {
        if (cert1 == cert2)
            return true;
        if (cert1 == null || cert2 == null)
            return false;
        try {
            return MessageDigest.isEqual(cert1.getEncoded(), cert2.getEncoded());
        } catch (CertificateEncodingException certificateException) {
            LOGGER.trace("Certificate encoding error", certificateException);
            return false;
        }
    }

    private Void keysPresentInRegisteredCerts(
            final Stream<CertificateVerificationKey> keys)
            throws CertificateException {
        List<CertificateVerificationKey> keysList = keys.toList();
        if (keysList.isEmpty()) {
            throw new CertificateException("Failed to find JWK entry in provided JWKSet which matches the X509 cert");
        }
        LOGGER.debug("Found {} registered certificates matching request {} certificate", keysList.size(),
                     transportCertPurpose.getLabel());
        return null;
    }

    /**
     * Heaplet responsible for creating {@link DefaultTransportCertValidator} objects
     * <pre>
     * {@code {
     *      "type": "DefaultTransportCertValidator",
     *      "config": {
     *          "transportCertSecretId" : expression<string> [OPTIONAL - The expected purpose to use to retrieve and
     *                                                                   validate the transport cert (1). Defaults to
     *                                                                   the generic "verifyCertificate" purpose (2).]
     *      }
     *   }
     * }
     * }
     * </pre>
     * <p>
     * Notes:
     * <ol>
     *     <li>
     *         Config 'transportCertSecretId' should be aligned with {@link CachingJwkSetService} config
     *         {@code #tlsTransportCertSecretId} which supports locating the transport cert, while constraining the JWKs
     *         available for the given purpose by 'use'. This ensures only JWKs with a matching {@code keyUse} are
     *         available, so preventing cross-JWK usage. For the Open Banking use case, the {@code JWK.use} value is
     *         expected to be {@value org.forgerock.json.jose.jwk.KeyUseConstants#TLS} for a cert that is used for MTLS
     *         purposes. This is a custom key use defined by Open Banking. In effect, 'transportCertSecretId' defines
     *         the purpose to be used to retrieve the transport cert JWKs, while the {@link CachingJwkSetService} config
     *         states that "on using this purpose, apply this JWK constraint (on keyUse 'tls')".
     *      </li>
     *      <li>
     *         See {@link Purpose#VERIFY_CERTIFICATE} for default purpose label if no key use is supplied, which is the
     *         general purpose {@link Purpose} to verify certificates.
     *     </li>
     *     </li>
     * </ol>
     * <p>
     * Example config:
     * <pre>
     * {
     *       "name": "OBTransportCertValidator",
     *       "type": "DefaultTransportCertValidator",
     *       "config": {
     *         "transportCertSecretId": "tls"
     *       }
     * }
     * </pre>
     */
    public static class Heaplet extends GenericHeaplet {

        // This key 'use' should align with the CachingJwkSetService.tlsTransportCertSecretId to match expected JWK use
        static final String CONFIG_TRANSPORT_CERT_SECRET_ID = "transportCertSecretId";
        static final String CONFIG_OLD_TRANSPORT_KEY_USE = "validKeyUse";
        static final String DEFAULT_TRANSPORT_CERT_SECRET_ID = VERIFY_CERTIFICATE.getLabel();

        @Override
        public Object create() throws HeapException {
            Purpose<CertificateVerificationKey> transportCertPurpose =
                    config.get(CONFIG_TRANSPORT_CERT_SECRET_ID)
                          .as(evaluatedWithHeapProperties())
                          .as(optionalOf(purposeOf(CertificateVerificationKey.class)))
                          .orElseGet(() -> this.checkForDeprecatedConfigAndWarn(config)
                                               .defaultTo(DEFAULT_TRANSPORT_CERT_SECRET_ID)
                                               .as(purposeOf(CertificateVerificationKey.class)));
            return new DefaultTransportCertValidator(transportCertPurpose);
        }

        private JsonValue checkForDeprecatedConfigAndWarn(final JsonValue config) {
            return config.get(CONFIG_OLD_TRANSPORT_KEY_USE)
                         // Check for old 'validKeyUse' - and warn of config removal
                         .as(evaluatedWithHeapProperties())
                         .as(json -> {
                             if (json.isNotNull()) {
                                 String jwkSetServiceConfigName =
                                         CachingJwkSetService.class.getSimpleName() + ".tlsTransportCertSecretId";
                                 LOGGER.warn("Config '{}' has been deprecated, please use '{}'." +
                                                     "Supplied value '{}' will be assumed to mean the secretId to " +
                                                     "retrieve transport keys (and should be aligned with '{}').",
                                             CONFIG_OLD_TRANSPORT_KEY_USE,
                                             CONFIG_TRANSPORT_CERT_SECRET_ID,
                                             json.asString(),
                                             jwkSetServiceConfigName);
                             }
                             return json;
                         });
        }
    }
}
