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
package com.forgerock.sapi.gateway.dcr.filter;

import static java.util.Objects.requireNonNull;
import static org.forgerock.http.protocol.Response.newResponsePromise;
import static org.forgerock.openig.fapi.dcr.common.ErrorCode.INVALID_SOFTWARE_STATEMENT;
import static org.forgerock.openig.fapi.dcr.common.ErrorResponseUtils.errorResponse;
import static org.forgerock.openig.fapi.jwks.JwkSetServicePurposes.transportPurpose;
import static org.forgerock.openig.util.JsonValues.requiredHeapObject;
import static org.forgerock.secrets.jwkset.JwkSetSecretStore.JwkPredicates.keyUse;
import static org.forgerock.util.promise.NeverThrowsException.neverThrown;
import static org.forgerock.util.promise.Promises.newExceptionPromise;
import static org.forgerock.util.promise.Promises.newResultPromise;

import java.net.URI;
import java.security.MessageDigest;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;

import org.forgerock.http.Filter;
import org.forgerock.http.Handler;
import org.forgerock.http.protocol.Request;
import org.forgerock.http.protocol.Response;
import org.forgerock.json.jose.jwk.JWK;
import org.forgerock.json.jose.jwk.JWKSet;
import org.forgerock.json.jose.jwk.KeyUseConstants;
import org.forgerock.openig.fapi.context.FapiContext;
import org.forgerock.openig.fapi.dcr.RegistrationRequest;
import org.forgerock.openig.fapi.dcr.SoftwareStatement;
import org.forgerock.openig.fapi.dcr.common.ErrorCode;
import org.forgerock.openig.fapi.dcr.common.RegistrationException;
import org.forgerock.openig.fapi.jwks.JwkSetService;
import org.forgerock.openig.heap.GenericHeaplet;
import org.forgerock.openig.heap.HeapException;
import org.forgerock.openig.util.Choice;
import org.forgerock.secrets.Purpose;
import org.forgerock.secrets.SecretConstraint;
import org.forgerock.secrets.jwkset.JwkSetSecretStore;
import org.forgerock.secrets.keys.CryptoKey;
import org.forgerock.secrets.keys.VerificationKey;
import org.forgerock.services.context.Context;
import org.forgerock.util.Options;
import org.forgerock.util.annotations.VisibleForTesting;
import org.forgerock.util.promise.NeverThrowsException;
import org.forgerock.util.promise.Promise;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * {@link Filter} responsible for validating the inbound request transport certificate, as found in the
 * {@link FapiContext}.
 */
public final class TransportCertValidationFilter implements Filter {
    private static final Logger logger = LoggerFactory.getLogger(TransportCertValidationFilter.class);

    private final JwkSetService jwkSetService;
    private final boolean allowIgIssuedTestCerts;

    public TransportCertValidationFilter(final JwkSetService jwkSetService, final boolean allowIgIssuedTestCerts) {
        this.jwkSetService = requireNonNull(jwkSetService);
        this.allowIgIssuedTestCerts = allowIgIssuedTestCerts;
    }

    @Override
    public Promise<Response, NeverThrowsException> filter(final Context context,
                                                          final Request request,
                                                          final Handler next) {
        FapiContext fapiContext =
                context.as(FapiContext.class)
                       .orElseThrow(() -> {
                           String errorMessage = ("Fapi initialization error - FapiInitializerFilter may not have "
                                   + "been configured: FapiContext not found");
                           return new IllegalStateException(errorMessage);
                       });

        RegistrationRequest registrationRequest = fapiContext.getRegistrationRequest();
        SoftwareStatement softwareStatement = registrationRequest.getSoftwareStatement();
        X509Certificate tlsClientCert = fapiContext.getClientCertificate();
        return testClientCert(tlsClientCert, softwareStatement, registrationRequest)
                       .thenAsync(ignore -> next.handle(context, request),
                           exception -> newResponsePromise(errorResponse(exception)));

    }

    private Promise<Void, RegistrationException> testClientCert(final X509Certificate tlsClientCert,
                                                                final SoftwareStatement softwareStatement,
                                                                final RegistrationRequest registrationRequest) {
        return getJwkSetLocator(softwareStatement)
                       .thenAsync(jwkSetService -> jwkSetService.applyAsync(
                               jwksUri -> {
                                   registrationRequest.setMetadata("jwks_uri", jwksUri.toString());
                                   return testCertAgainstJwksUri(tlsClientCert, jwksUri);
                               },
                               jwkSet -> {
                                   if (!allowIgIssuedTestCerts) {
                                       return newExceptionPromise(new RegistrationException(
                                               ErrorCode.INVALID_CLIENT_METADATA,
                                               "software_statement must contain software_jwks_endpoint"));
                                   }
                                   registrationRequest.setMetadata("jwks", jwkSet.toJsonValue());
                                   return testCertAgainstJwkSet(tlsClientCert, jwkSet);
                               }));
    }

    private Promise<Choice<URI, JWKSet>, RegistrationException> getJwkSetLocator(final SoftwareStatement softwareStatement) {
        // Managed as a Promise to avoid explicitly handling the `Choice#applyAsync` thrown exception <E> (checked
        // RegistrationException). This part extracted due to compiler Promises type handling.
        return newResultPromise(softwareStatement.getJwkSetLocator());
    }

    private Promise<Void, RegistrationException> testCertAgainstJwksUri(final X509Certificate tlsClientCert,
                                                                        final URI jwksUri) {
        logger.debug("Checking cert against ssa software_jwks_endpoint: {}", jwksUri);
        return jwkSetService.getJwkSetSecretStore(jwksUri)
                            .thenAsync(jwkSetSecretStore ->
                                               testCertInJwkSetSecretStore(tlsClientCert, jwkSetSecretStore),
                                       failedToLoadJwkException -> {
                                           // getJwkSetSecretStore may fail with a FailedToLoadJwkException
                                           throw new RegistrationException(ErrorCode.INVALID_CLIENT_METADATA,
                                                                           failedToLoadJwkException.getMessage(),
                                                                           failedToLoadJwkException);
                                       });
    }

    private static Promise<Void, RegistrationException> testCertAgainstJwkSet(final X509Certificate tlsClientCert,
                                                                              final JWKSet jwkSet) {
        if (logger.isDebugEnabled()) {
            logger.debug("Checking cert against ssa JWKS: {}",
                         jwkSet.getJWKsAsList().stream().map(JWK::getKeyId).toList());
        }
        JwkSetSecretStore jwkSetSecretStore = new JwkSetSecretStore(jwkSet, Options.defaultOptions())
                .withPurposePredicate(transportPurpose(), keyUse(KeyUseConstants.TLS));
        return testCertInJwkSetSecretStore(tlsClientCert, jwkSetSecretStore);
    }

    private static Promise<Void, RegistrationException> testCertInJwkSetSecretStore(
            final X509Certificate tlsClientCert,
            final JwkSetSecretStore jwkSetSecretStore) {
        Purpose<VerificationKey> tlsPurpose = transportPurpose()
                .withConstraints(matchesX509Cert(tlsClientCert));
        return jwkSetSecretStore.getValid(tlsPurpose)
                                .then(secrets -> {
                                    if (secrets.findAny().isEmpty()) {
                                        throw new RegistrationException(
                                                INVALID_SOFTWARE_STATEMENT,
                                                "tls transport cert does not match any certs " +
                                                        "registered in jwks for software statement");
                                    }
                                    return null;
                                }, neverThrown())
                                // We only care that it's present - Void
                                .thenDiscardResult();
    }

    private static SecretConstraint<CryptoKey> matchesX509Cert(final X509Certificate tlsClientCert) {
        // Note that this emulates the real way in which an X.509 cert will be validated via a JwkSetSecretStore
        return secret -> {
            try {
                tlsClientCert.checkValidity();
            } catch (CertificateExpiredException | CertificateNotYetValidException ignored) {
                return false;
            }
            return secret.getCertificate(X509Certificate.class)
                         .filter(x509Cert -> x509CertsEqual(x509Cert, tlsClientCert))
                         .map(x509Cert -> {
                             logger.debug("Found matching cert {}", x509Cert.getSerialNumber());
                             return x509Cert;
                         })
                         .isPresent();
        };
    }

    @VisibleForTesting
    static boolean x509CertsEqual(final X509Certificate cert1, final X509Certificate cert2) {
        try {
            if (cert1 == cert2) {
                // Test that cert encoding is valid (does not raise) to be consistent with comparing different certs
                cert1.getEncoded();
                return true;
            }
            if (cert1 == null || cert2 == null) {
                return false;
            }
            return MessageDigest.isEqual(cert1.getEncoded(), cert2.getEncoded());
        } catch (CertificateEncodingException certificateException) {
            logger.trace("Certificate encoding error", certificateException);
            return false;
        }
    }

    public static class Heaplet extends GenericHeaplet {

        /** Public name used by resolver. */
        public static final String NAME = "DcrTransportCertValidationFilter";

        static final String CONFIG_ALLOW_IG_ISSUED_CERTS = "allowIgIssuedTestCerts";
        static final String CONFIG_JWK_SET_SERVICE = "jwkSetService";

        @Override
        public Object create() throws HeapException {
            JwkSetService jwkSetService = config.get(CONFIG_JWK_SET_SERVICE)
                                                .as(evaluatedWithHeapProperties())
                                                .as(requiredHeapObject(heap, JwkSetService.class));
            boolean allowIgIssuedTestCerts = config.get(CONFIG_ALLOW_IG_ISSUED_CERTS)
                                                   .as(evaluatedWithHeapProperties())
                                                   .defaultTo(false)
                                                   .asBoolean();
            return new TransportCertValidationFilter(jwkSetService, allowIgIssuedTestCerts);
        }
    }
}
