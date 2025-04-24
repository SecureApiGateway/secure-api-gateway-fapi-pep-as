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
import static org.forgerock.openig.fapi.jwks.JwkSetServicePurposes.transportPurpose;
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
import org.forgerock.json.jose.jwk.KeyUseConstants;
import org.forgerock.openig.fapi.jwks.JwkSetService;
import org.forgerock.openig.heap.GenericHeaplet;
import org.forgerock.openig.heap.HeapException;
import org.forgerock.secrets.Purpose;
import org.forgerock.secrets.SecretConstraint;
import org.forgerock.secrets.jwkset.JwkSetSecretStore;
import org.forgerock.secrets.keys.CryptoKey;
import org.forgerock.secrets.keys.VerificationKey;
import org.forgerock.util.promise.Promise;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Certificate validation is achieved by comparing the incoming {@link X509Certificate client certificate} with
 * those obtained from the client {@link JwkSetSecretStore JWKSet}. That is, we obtain valid certificates for the
 * expected {@code transportCertSecretId} from the JWKSet and compare the client certificate with these certificates
 * to find a match.
 * <p>
 * For the Open Banking use case, the {@code JWK.use} value is expected to be
 * {@value org.forgerock.json.jose.jwk.KeyUseConstants#TLS} for a cert that is used for MTLS purposes. This is a custom
 * key use defined by Open Banking.
 */
public class DefaultTransportCertValidator implements TransportCertValidator {

    private static final Logger LOGGER = LoggerFactory.getLogger(DefaultTransportCertValidator.class);


    public DefaultTransportCertValidator() {
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
        Purpose<VerificationKey> certConstrainedPurpose = transportPurpose()
                .withConstraints(matchesX509Cert(clientCertificate));
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
            final Stream<VerificationKey> keys)
            throws CertificateException {
        List<VerificationKey> keysList = keys.toList();
        if (keysList.isEmpty()) {
            throw new CertificateException("Failed to find JWK entry in provided JWKSet which matches the X509 cert");
        }
        LOGGER.debug("Found {} registered certificates matching request {} certificate",
                     keysList.size(),
                     transportPurpose().getLabel());
        return null;
    }

    /**
     * Heaplet responsible for creating {@link DefaultTransportCertValidator} objects. Note that this filter uses a
     * <p>
     * Example config:
     * <pre>
     * {
     *       "name": "OBTransportCertValidator",
     *       "type": "DefaultTransportCertValidator"
     * }
     * </pre>
     */
    public static class Heaplet extends GenericHeaplet {

        static final String CONFIG_OLD_TRANSPORT_KEY_USE = "validKeyUse";

        @Override
        public Object create() throws HeapException {
            checkForDeprecatedConfigAndWarn(config);
            return new DefaultTransportCertValidator();
        }

        private void checkForDeprecatedConfigAndWarn(final JsonValue config) {
            String validKeyUse = config.get(CONFIG_OLD_TRANSPORT_KEY_USE)
                                       .as(evaluatedWithHeapProperties())
                                       .asString();
            if (validKeyUse != null) {
                LOGGER.warn("Config '{}' has been deprecated, {}-exposed '{}' purpose is used to obtain valid "
                                    + "transport secrets, and key use is constrained to '{}'",
                            CONFIG_OLD_TRANSPORT_KEY_USE,
                            JwkSetService.class.getSimpleName(),
                            transportPurpose().getLabel(),
                            KeyUseConstants.TLS);
            }
        }
    }
}
