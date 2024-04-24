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

import com.forgerock.sapi.gateway.dcr.filter.FetchApiClientFilter;
import com.forgerock.sapi.gateway.dcr.filter.ResponsePathFetchApiClientFilter;
import com.forgerock.sapi.gateway.dcr.models.ApiClient;
import com.forgerock.sapi.gateway.jwks.ApiClientJwkSetService;
import com.forgerock.sapi.gateway.jwks.DefaultApiClientJwkSetService;
import com.forgerock.sapi.gateway.jwks.JwkSetService;
import com.forgerock.sapi.gateway.trusteddirectories.TrustedDirectory;
import com.forgerock.sapi.gateway.trusteddirectories.TrustedDirectoryService;

/**
 * Filter to validate that the client's MTLS transport certificate is valid when making a request to an Authorisation
 * Server endpoint.
 * <p>
 * This is a specialised version of {@link TransportCertValidationFilter}, it does the same validation,
 * but has been adapted to do its validation on the response path. By deferring the validation to the response
 * path then we can be sure that we have an authenticated client.
 * <p>
 * This filter depends on the {@link ApiClient} being present in the {@link AttributesContext}.
 * This is typically achieved by installing a {@link ResponsePathFetchApiClientFilter} after this filter in the chain.
 * <p>
 * A configurable {@link CertificateRetriever} is used to retrieve the client's MTLS certificate. This is then validated
 * against the JWKSet for the ApiClient by using a {@link TransportCertValidator}.
 * <p>
 * If the validation is successful the Authorisation Server Response is passed on along the filter chain. Otherwise,
 * an error response is returned with 400 BAD_REQUEST status.
 * <p>
 * See {@link Heaplet} for filter configuration options.
 */
public class ResponsePathTransportCertValidationFilter implements Filter {

    private final Logger logger = LoggerFactory.getLogger(getClass());

    /**
     * Retrieves the client's mTLS certificate
     */
    private final CertificateRetriever certificateRetriever;

    /**
     * Service which retrieves {@link TrustedDirectory} configuration
     */
    private final TrustedDirectoryService trustedDirectoryService;

    /**
     * Service which retrieves the {@link org.forgerock.json.jose.jwk.JWKSet} for the {@link ApiClient}
     */
    private final ApiClientJwkSetService apiClientJwkSetService;

    /**
     * Validator which ensures that the client's mTLS certificate belongs to the ApiClient's {@link org.forgerock.json.jose.jwk.JWKSet}
     */
    private final TransportCertValidator transportCertValidator;

    public ResponsePathTransportCertValidationFilter(TrustedDirectoryService trustedDirectoryService,
                                                      ApiClientJwkSetService apiClientJwkSetService,
                                                      CertificateRetriever certificateRetriever,
                                                      TransportCertValidator transportCertValidator) {
        Reject.ifNull(trustedDirectoryService, "trustedDirectoryService must be provided");
        Reject.ifNull(apiClientJwkSetService, "apiClientJwkSetService must be provided");
        Reject.ifNull(certificateRetriever, "certificateRetriever must be provided");
        Reject.ifNull(transportCertValidator, "transportCertValidator must be provided");
        this.trustedDirectoryService = trustedDirectoryService;
        this.apiClientJwkSetService = apiClientJwkSetService;
        this.certificateRetriever = certificateRetriever;
        this.transportCertValidator = transportCertValidator;
    }

    @Override
    public Promise<Response, NeverThrowsException> filter(Context context, Request request, Handler next) {
        final X509Certificate clientCertificate;
        try {
             clientCertificate = certificateRetriever.retrieveCertificate(context, request);
        } catch (CertificateException e) {
            logger.error("Failed to resolve client mtls certificate", e);
            return Promises.newResultPromise(createErrorResponse(e.getMessage()));
        }

        // Defer cert validation until the response path, then we know that the client authenticated successfully
        return next.handle(context, request).thenAsync(response -> {
            // Allow errors to pass on up the chain
            if (!response.getStatus().isSuccessful()) {
                return Promises.newResultPromise(response);
            } else {
                final ApiClient apiClient = FetchApiClientFilter.getApiClientFromContext(context);
                if (apiClient == null) {
                    logger.warn("Unable to validate transport cert - " +
                            "ApiClient could not be fetched from the attributes context");
                    return Promises.newResultPromise(createErrorResponse("ApiClient not found"));
                }
                return validateApiClientTransportCert(apiClient, clientCertificate, response);
            }
        });
    }

    private Promise<Response, NeverThrowsException> validateApiClientTransportCert(ApiClient apiClient,
                                                                                   X509Certificate clientCertificate,
                                                                                   Response response) {
        final TrustedDirectory trustedDirectory = trustedDirectoryService.getTrustedDirectoryConfiguration(apiClient);
        if (trustedDirectory == null) {
            logger.error("Failed to get trusted directory for apiClient: {}", apiClient);
            return Promises.newResultPromise(new Response(Status.INTERNAL_SERVER_ERROR));
        }

        return apiClientJwkSetService.getJwkSet(apiClient, trustedDirectory).then(jwkSet -> {
            try {
                transportCertValidator.validate(clientCertificate, jwkSet);
            } catch (CertificateException ce) {
                logger.error("Failed to validate that the supplied client certificate", ce);
                return createErrorResponse(ce.getMessage());
            }
            // Successfully validated the client's cert, allow the original response to continue along the filter chain.
            logger.debug("Transport cert validated successfully");
            return response;
        }, ex -> {
            logger.error("Failed to get JWKS for apiClient: {}", apiClient, ex);
            return new Response(Status.INTERNAL_SERVER_ERROR);
        });
    }

    /**
     * Creates an error response conforming to spec: https://www.rfc-editor.org/rfc/rfc6749#section-5.2
     *
     * @param message String error message to use in the error_description response field
     * @return Response object communicating an error as per the spec
     */
    private Response createErrorResponse(String message) {
        return new Response(Status.UNAUTHORIZED).setEntity(json(object(field("error", "invalid_client"),
                                                                       field("error_description", message))));
    }

    /**
     * Heaplet used to create {@link ResponsePathTransportCertValidationFilter} objects
     * <p>
     * Mandatory fields:
     * <p>
     *  - trustedDirectoryService: the name of a {@link TrustedDirectoryService} object on the heap
     *  - jwkSetService: the name of the service (defined in config on the heap) that can obtain JWK Sets from a jwk set url
     *  - transportCertValidator: the name of a {@link TransportCertValidator} object on the heap to use to validate the certs
     *  - certificateRetriever: a {@link CertificateRetriever} object heap reference used to retrieve the client's
     *                          certificate to validate.
     * Example config:
     * <pre>{@code
     * {
     *           "name": "ResponsePathTransportCertValidationFilter",
     *           "type": "ResponsePathTransportCertValidationFilter",
     *           "comment": "Validate the client's MTLS transport cert",
     *           "config": {
     *             "certificateRetriever": "HeaderCertificateRetriever",
     *             "trustedDirectoryService": "TrustedDirectoriesService",
     *             "jwkSetService": "OBJwkSetService",
     *             "transportCertValidator": "TransportCertValidator"
     *           }
     * }
     * }</pre>
     */
    public static class Heaplet extends GenericHeaplet {

        @Override
        public Object create() throws HeapException {
            final TrustedDirectoryService trustedDirectoryService = config.get("trustedDirectoryService")
                    .as(requiredHeapObject(heap, TrustedDirectoryService.class));

            final JwkSetService jwkSetService = config.get("jwkSetService").as(requiredHeapObject(heap, JwkSetService.class));
            final ApiClientJwkSetService apiClientJwkSetService = new DefaultApiClientJwkSetService(jwkSetService);

            final TransportCertValidator transportCertValidator = config.get("transportCertValidator").required()
                    .as(requiredHeapObject(heap, TransportCertValidator.class));

            final CertificateRetriever certificateRetriever = config.get("certificateRetriever")
                                                                    .as(requiredHeapObject(heap, CertificateRetriever.class));

            return new ResponsePathTransportCertValidationFilter(trustedDirectoryService, apiClientJwkSetService,
                                                                  certificateRetriever, transportCertValidator);

        }
    }
}
