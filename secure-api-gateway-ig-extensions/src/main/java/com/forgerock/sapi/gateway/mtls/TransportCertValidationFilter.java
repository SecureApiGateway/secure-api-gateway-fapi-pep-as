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
import static org.forgerock.http.protocol.Response.newResponsePromise;
import static org.forgerock.json.JsonValue.field;
import static org.forgerock.json.JsonValue.json;
import static org.forgerock.json.JsonValue.object;
import static org.forgerock.json.JsonValueFunctions.optional;
import static org.forgerock.openig.util.JsonValues.optionalHeapObject;
import static org.forgerock.openig.util.JsonValues.requiredHeapObject;
import static org.forgerock.util.LambdaExceptionUtils.rethrowFunction;
import static org.forgerock.util.LambdaExceptionUtils.rethrowSupplier;

import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import org.forgerock.http.Filter;
import org.forgerock.http.Handler;
import org.forgerock.http.protocol.Request;
import org.forgerock.http.protocol.Response;
import org.forgerock.http.protocol.Status;
import org.forgerock.json.jose.exceptions.FailedToLoadJWKException;
import org.forgerock.openig.fapi.apiclient.ApiClient;
import org.forgerock.openig.fapi.context.FapiContext;
import org.forgerock.openig.heap.GenericHeaplet;
import org.forgerock.openig.heap.HeapException;
import org.forgerock.secrets.jwkset.JwkSetSecretStore;
import org.forgerock.services.context.AttributesContext;
import org.forgerock.services.context.Context;
import org.forgerock.util.promise.NeverThrowsException;
import org.forgerock.util.promise.Promise;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.forgerock.sapi.gateway.dcr.filter.FetchApiClientFilter;

/**
 * Filter to validate that the client's MTLS transport certificate is valid.
 * <p>
 * This filter depends on the {@link ApiClient} being present in the {@link AttributesContext}.
 * Once the {@link X509Certificate} and JWKSet have been obtained, then the filter delegates to a {@link TransportCertValidator}
 * to do the validation.
 * If the validator successfully validates the certificate, then the request is passed to the next filter in the chain,
 * otherwise a HTTP 400 response is returned.
 */
public class TransportCertValidationFilter implements Filter {

    private static final Logger logger = LoggerFactory.getLogger(TransportCertValidationFilter.class.getName());

    /**
     * Validator which checks if the client's MTLS certificate is valid.
     */
    private final TransportCertValidator transportCertValidator;

    public TransportCertValidationFilter(TransportCertValidator transportCertValidator) {
        requireNonNull(transportCertValidator, "transportCertValidator must be provided");
        this.transportCertValidator = transportCertValidator;
    }

    private static Response errorResponse(String message) {
        return new Response(Status.BAD_REQUEST).setEntity(json(object(field("error_description", message))));
    }

    @Override
    public Promise<Response, NeverThrowsException> filter(Context context, Request request, Handler next) {
        logger.debug("Attempting to validate transport cert");
        FapiContext fapiContext = context.asContext(FapiContext.class);
        final X509Certificate certificate = fapiContext.getClientCertificate();
        if (certificate == null) {
            return newResponsePromise(
                    errorResponse("client tls certificate must be provided as a valid x509 certificate"));
        }
        return getJwkSetSecretStore(fapiContext)
                .thenAsync(jwkSetSecretStore ->
                                   transportCertValidator.validate(certificate, jwkSetSecretStore)
                                                         .thenAsync(ignored -> next.handle(context, request),
                                                                    ce -> handleCertException()),
                loadJwkException -> {
                    logger.debug("Failed to load JwkSet", loadJwkException);
                    return newResponsePromise(errorResponse("Failed to get client JWKSet"));
                });
    }

    private Promise<JwkSetSecretStore, FailedToLoadJWKException> getJwkSetSecretStore(FapiContext context) {
        final ApiClient apiClient = FetchApiClientFilter.getApiClientFromContext(context);
        if (apiClient == null) {
            logger.error("apiClient not found in request context");
            throw new IllegalStateException("apiClient not found in request context");
        }
        return apiClient.getJwkSetSecretStore();
    }

    private static Promise<Response, NeverThrowsException> handleCertException() {
        logger.debug("Transport cert failed validation: not present in JWKS or present with wrong \"use\"");
        return newResponsePromise(errorResponse("client tls certificate not found in JWKS for software statement"));
    }

    /**
     * Heaplet used to create {@link TransportCertValidationFilter} objects
     * <p>
     * Mandatory fields:
     *  - transportCertValidator: the name of a {@link TransportCertValidator} object on the heap to use to validate the certs
     * <p>
     * Example config:
     * {
     *           "comment": "Validate the MTLS transport cert",
     *           "name": "TransportCertValidationFilter",
     *           "type": "TransportCertValidationFilter",
     *           "config": {
     *             "transportCertValidator": "TransportCertValidator"
     *           }
     * }
     */
    public static class Heaplet extends GenericHeaplet {
        static final String CONFIG_CERT_VALIDATOR = "transportCertValidator";

        @Override
        public Object create() throws HeapException {
            TransportCertValidator transportCertValidator = config.get(CONFIG_CERT_VALIDATOR)
                                                                  .required()
                                                                  .as(requiredHeapObject(heap,
                                                                                         TransportCertValidator.class));
            return new TransportCertValidationFilter(transportCertValidator);
        }
    }
}
