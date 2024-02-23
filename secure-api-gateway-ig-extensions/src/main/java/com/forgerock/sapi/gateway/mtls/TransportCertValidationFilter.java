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

import static org.forgerock.json.JsonValue.field;
import static org.forgerock.json.JsonValue.json;
import static org.forgerock.json.JsonValue.object;
import static org.forgerock.openig.util.JsonValues.requiredHeapObject;

import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import org.forgerock.http.Filter;
import org.forgerock.http.Handler;
import org.forgerock.http.protocol.Request;
import org.forgerock.http.protocol.Response;
import org.forgerock.http.protocol.Status;
import org.forgerock.json.JsonValue;
import org.forgerock.json.jose.jwk.JWKSet;
import org.forgerock.openig.heap.GenericHeaplet;
import org.forgerock.openig.heap.HeapException;
import org.forgerock.services.context.AttributesContext;
import org.forgerock.services.context.Context;
import org.forgerock.util.Reject;
import org.forgerock.util.promise.NeverThrowsException;
import org.forgerock.util.promise.Promise;
import org.forgerock.util.promise.Promises;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.forgerock.sapi.gateway.dcr.models.ApiClient;
import com.forgerock.sapi.gateway.jwks.FetchApiClientJwksFilter;

/**
 * Filter to validate that the client's MTLS transport certificate is valid.
 *
 * This filter depends on the {@link JWKSet} containing the keys for this {@link ApiClient} being present in
 * the {@link AttributesContext}.
 *
 * The certificate for the request is supplied by the pluggable certificateRetriever, see {@link HeaderCertificateRetriever}
 * for an example implementation (this is the default configured by the {@link Heaplet})
 *
 * Once the {@link X509Certificate} and JWKSet have been obtained, then the filter delegates to a {@link TransportCertValidator}
 * to do the validation.
 * If the validator successfully validates the certificate, then the request is passed to the next filter in the chain,
 * otherwise a HTTP 400 response is returned.
 */
public class TransportCertValidationFilter implements Filter {

    private final Logger logger = LoggerFactory.getLogger(getClass());

    /**
     * Retrieves the client's x509 certificate used for mutual TLS
     */
    private final CertificateRetriever certificateRetriever;

    /**
     * Validator which checks if the client's MTLS certificate is valid.
     */
    private final TransportCertValidator transportCertValidator;

    public TransportCertValidationFilter(CertificateRetriever certificateRetriever,
                                        TransportCertValidator transportCertValidator) {
        Reject.ifNull(certificateRetriever, "certificateRetriever must be provided");
        Reject.ifNull(transportCertValidator, "transportCertValidator must be provided");
        this.certificateRetriever = certificateRetriever;
        this.transportCertValidator = transportCertValidator;
    }

    private Response createErrorResponse(String message) {
        return new Response(Status.BAD_REQUEST).setEntity(json(object(field("error_description", message))));
    }

    @Override
    public Promise<Response, NeverThrowsException> filter(Context context, Request request, Handler next) {
        logger.debug("Attempting to validate transport cert");

        final JWKSet jwkSet = getJwkSet(context);

        final X509Certificate certificate;
        try {
            certificate = certificateRetriever.retrieveCertificate(context, request);
        } catch (CertificateException e) {
            logger.warn("Transport cert not valid", e);
            return Promises.newResultPromise(createErrorResponse("client tls certificate must be provided as a valid x509 certificate"));
        }

        try {
            transportCertValidator.validate(certificate, jwkSet);
            logger.debug("Transport cert validated successfully");
            return next.handle(context, request);
        } catch (CertificateException e) {
            logger.debug("Transport cert failed validation: not present in JWKS or present with wrong \"use\"");
            return Promises.newResultPromise(createErrorResponse("client tls certificate not found in JWKS for software statement"));
        }
    }

    private JWKSet getJwkSet(Context context) {
        final JWKSet apiClientJwkSet = FetchApiClientJwksFilter.getApiClientJwkSetFromContext(context);
        if (apiClientJwkSet == null) {
            logger.error("apiClientJwkSet not found in request context");
            throw new IllegalStateException("apiClientJwkSet not found in request context");
        }
        return apiClientJwkSet;
    }

    /**
     * Heaplet used to create {@link TransportCertValidationFilter} objects
     *
     * Mandatory fields:
     *  - transportCertValidator: the name of a {@link TransportCertValidator} object on the heap to use to validate the certs
     *
     * Optional fields:
     * - certificateRetriever: a {@link CertificateRetriever} object heap reference used to retrieve the client's
     *                         certificate to validate.
     * - clientTlsCertHeader: (Deprecated - Use certificateRetriever config instead)
     *                        the name of the Request Header which contains the client's TLS cert
     *
     * Example config:
     * {
     *           "comment": "Validate the MTLS transport cert",
     *           "name": "TransportCertValidationFilter",
     *           "type": "TransportCertValidationFilter",
     *           "config": {
     *             "certificateRetriever": "HeaderCertificateRetriever",
     *             "transportCertValidator": "TransportCertValidator"
     *           }
     * }
     */
    public static class Heaplet extends GenericHeaplet {

        private final Logger logger = LoggerFactory.getLogger(getClass());

        @Override
        public Object create() throws HeapException {
            final CertificateRetriever certificateRetriever;
            // certificateRetriever configuration is preferred to the deprecated clientTlsCertHeader configuration
            final JsonValue certificateRetrieverConfig = config.get("certificateRetriever");
            if (certificateRetrieverConfig.isNotNull()) {
                certificateRetriever = certificateRetrieverConfig.as(requiredHeapObject(heap, CertificateRetriever.class));
            } else {
                // Fallback to the config which only configures the HeaderCertificateRetriever
                final String clientCertHeaderName = config.get("clientTlsCertHeader").required().asString();
                logger.warn("{} config option clientTlsCertHeader is deprecated, use certificateRetriever instead. " +
                                "This option needs to contain a value which is a reference to a {} object on the heap",
                        TransportCertValidationFilter.class.getSimpleName(), CertificateRetriever.class);
                certificateRetriever = new HeaderCertificateRetriever(clientCertHeaderName);
            }
            final TransportCertValidator transportCertValidator = config.get("transportCertValidator").required()
                                                                        .as(requiredHeapObject(heap, TransportCertValidator.class));
            return new TransportCertValidationFilter(certificateRetriever, transportCertValidator);
        }
    }
}
