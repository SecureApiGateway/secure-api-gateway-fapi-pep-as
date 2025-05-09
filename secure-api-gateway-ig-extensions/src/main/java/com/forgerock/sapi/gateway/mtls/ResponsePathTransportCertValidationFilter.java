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
import static org.forgerock.http.protocol.Responses.newInternalServerError;
import static org.forgerock.json.JsonValue.field;
import static org.forgerock.json.JsonValue.json;
import static org.forgerock.json.JsonValue.object;

import java.security.cert.X509Certificate;

import org.forgerock.http.Filter;
import org.forgerock.http.Handler;
import org.forgerock.http.protocol.Request;
import org.forgerock.http.protocol.Response;
import org.forgerock.http.protocol.Status;
import org.forgerock.openig.fapi.apiclient.ApiClient;
import org.forgerock.openig.fapi.context.FapiContext;
import org.forgerock.openig.fapi.dcr.filter.DefaultTransportCertValidator;
import org.forgerock.openig.fapi.dcr.filter.TransportCertValidator;
import org.forgerock.openig.heap.GenericHeaplet;
import org.forgerock.openig.heap.HeapException;
import org.forgerock.secrets.jwkset.JwkSetSecretStore;
import org.forgerock.services.context.AttributesContext;
import org.forgerock.services.context.Context;
import org.forgerock.util.promise.NeverThrowsException;
import org.forgerock.util.promise.Promise;
import org.forgerock.util.promise.Promises;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.forgerock.sapi.gateway.dcr.filter.FetchApiClientFilter;
import com.forgerock.sapi.gateway.dcr.filter.ResponsePathFetchApiClientFilter;

/**
 * {@link Filter} responsible for validating the inbound request's {@link X509Certificate TLS transport certificate},
 * when making a request to an Authorisation Server endpoint.
 *
 * <p>Note that this is a specialised alternative to the {@link TransportCertValidationFilter}, which does the same
 * validation, but does so on the <i>response path</i>. By deferring the validation to the response path we can be sure
 * that we have an authenticated client, and been provisioned with the client's {@link ApiClient} (via the authorization
 * response).
 *
 * <p>This filter should be used in flows where, the JWKs to verify the certificate against are obtained from
 * the {@link ApiClient} associated with the <i>authenticated</i> registration request, which should be present on the
 * {@link FapiContext} following authorization, through inclusion of a {@link ResponsePathFetchApiClientFilter} later
 * in the chain.
 *
 * <pre>
 * {@code {
 *    "type": "TransportCertValidationFilter"
 * }
 * }
 * </pre>
 * @see TransportCertValidationFilter
 * @see TransportCertValidator TransportCertValidator is used to validate an X509Certificate against a JwkSetSecretStore
 */
public class ResponsePathTransportCertValidationFilter implements Filter {

    private final Logger logger = LoggerFactory.getLogger(getClass());

    /**
     * Controls whether the mTLS certificate is required for all requests processed by this filter.
     * If it is not required, then validation is skipped if it is not presented, with the request passing along
     * the filter chain.
     */
    private final boolean certificateIsMandatory;

    /**
     * Validator which ensures that the client's mTLS certificate belongs to the ApiClient's {@link org.forgerock.json.jose.jwk.JWKSet}
     */
    private final TransportCertValidator transportCertValidator;

    public ResponsePathTransportCertValidationFilter(final TransportCertValidator transportCertValidator,
                                                     final boolean certificateIsMandatory) {
        requireNonNull(transportCertValidator, "transportCertValidator must be provided");
        this.transportCertValidator = transportCertValidator;
        this.certificateIsMandatory = certificateIsMandatory;
    }

    @Override
    public Promise<Response, NeverThrowsException> filter(Context context, Request request, Handler next) {
        FapiContext fapiContext = context.asContext(FapiContext.class);
        X509Certificate clientCertificate = fapiContext.getClientCertificate();
        if (!certificateIsMandatory && clientCertificate == null) {
            // Skip validation for the case where the cert does not exist and it is optional
            logger.debug("Skipping cert validation, cert not found and validation is optional");
            return next.handle(context, request);
        } else if (certificateIsMandatory && clientCertificate == null) {
            return Promises.newResultPromise(unauthorizedResponse("client mtls certificate must be provided"));
        }

        // Defer cert validation until the response path, then we know that the client authenticated successfully
        return next.handle(context, request).thenAsync(response -> {
            // Allow errors to pass on up the chain
            if (!response.getStatus().isSuccessful()) {
                return Promises.newResultPromise(response);
            } else {
                final ApiClient apiClient = FetchApiClientFilter.getApiClientFromContext(fapiContext);
                if (apiClient == null) {
                    logger.warn("Unable to validate transport cert - " +
                            "ApiClient could not be fetched from the FAPI context");
                    return Promises.newResultPromise(unauthorizedResponse("ApiClient not found"));
                }
                return apiClient.getJwkSetSecretStore()
                                .thenAsync(jwkSetSecretStore ->
                                                   validateCertificate(clientCertificate, jwkSetSecretStore, response),
                                           loadJwkException ->
                                                   newResponsePromise(newInternalServerError()));
            }
        });
    }

    private Promise<Response, NeverThrowsException> validateCertificate(final X509Certificate clientCertificate,
                                                                        final JwkSetSecretStore jwkSetSecretStore,
                                                                        final Response response) {
        return transportCertValidator.validate(clientCertificate, jwkSetSecretStore)
                                     .then(ignored -> response,
                                           certException -> {
                                               logger.error("Failed to validate that the supplied client certificate",
                                                            certException);
                                               return unauthorizedResponse(certException.getMessage());
                                           });
    }

    /*
     * Creates an UNAUTHORIZED error response conforming to spec:
     * <a href="https://www.rfc-editor.org/rfc/rfc6749#section-5.2">rfc6749</a>
     */
    private Response unauthorizedResponse(String message) {
        return new Response(Status.UNAUTHORIZED).setEntity(json(object(field("error", "invalid_client"),
                                                                       field("error_description", message))));
    }

    /**
     * Heaplet used to create {@code TokenEndpointTransportCertValidationFilter} or
     * {@code ParEndpointTransportCertValidationFilter} objects.
     * <p>
     * Mandatory fields:
     * <p>
     *  - transportCertValidator: the name of a {@link TransportCertValidator} object on the heap to use to validate the certs
     * Example config:
     * <pre>{@code
     * {
     *           "name": "TokenEndpointTransportCertValidationFilter or ParEndpointTransportCertValidationFilter",
     *           "type": "TokenEndpointTransportCertValidationFilter or ParEndpointTransportCertValidationFilter",
     *           "comment": "Validate the client's MTLS transport cert",
     *           "config": {
     *             "transportCertValidator": "TransportCertValidator"
     *           }
     * }
     * }</pre>
     */
    private static class ResponsePathTransportCertValidationFilterHeaplet extends GenericHeaplet {

        private final boolean certificateIsMandatory;

        public ResponsePathTransportCertValidationFilterHeaplet(boolean certificateIsMandatory) {
            this.certificateIsMandatory = certificateIsMandatory;
        }

        @Override
        public Object create() throws HeapException {
            TransportCertValidator transportCertValidator = new DefaultTransportCertValidator();
            return new ResponsePathTransportCertValidationFilter(transportCertValidator,
                                                                 certificateIsMandatory);

        }
    }

    /**
     * Heaplet supporting creation of {@code TokenEndpointTransportCertValidationFilter}s. The transport cert must
     * always be passed to the token endpoint as it is mandatory for sender constrained access tokens.
     */
    public static class TokenEndpointTransportCertValidationFilterHeaplet
            extends ResponsePathTransportCertValidationFilterHeaplet {
        public TokenEndpointTransportCertValidationFilterHeaplet() {
            super(true);
        }
    }

    /**
     * Heaplet supporting creation of {@code ParEndpointTransportCertValidationFilter}s. The transport cert is optional
     * for PAR, it is only required when doing {@code tls_client_auth}.
     */
    public static class ParEndpointTransportCertValidationFilterHeaplet
            extends ResponsePathTransportCertValidationFilterHeaplet {
        public ParEndpointTransportCertValidationFilterHeaplet() {
            super(false);
        }
    }
}
