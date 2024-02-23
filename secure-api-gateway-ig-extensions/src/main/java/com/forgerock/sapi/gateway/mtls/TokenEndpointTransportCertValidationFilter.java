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

import static com.forgerock.sapi.gateway.dcr.filter.FetchApiClientFilter.createAddApiClientToContextResultHandler;
import static org.forgerock.json.JsonValue.field;
import static org.forgerock.json.JsonValue.json;
import static org.forgerock.json.JsonValue.object;
import static org.forgerock.openig.util.JsonValues.requiredHeapObject;

import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import org.forgerock.http.Client;
import org.forgerock.http.Filter;
import org.forgerock.http.Handler;
import org.forgerock.http.protocol.Request;
import org.forgerock.http.protocol.Response;
import org.forgerock.http.protocol.Status;
import org.forgerock.json.JsonValue;
import org.forgerock.json.jose.common.JwtReconstruction;
import org.forgerock.json.jose.jws.SignedJwt;
import org.forgerock.openig.heap.GenericHeaplet;
import org.forgerock.openig.heap.HeapException;
import org.forgerock.services.context.Context;
import org.forgerock.util.AsyncFunction;
import org.forgerock.util.Reject;
import org.forgerock.util.promise.NeverThrowsException;
import org.forgerock.util.promise.Promise;
import org.forgerock.util.promise.Promises;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.forgerock.sapi.gateway.dcr.service.ApiClientService;
import com.forgerock.sapi.gateway.dcr.service.idm.IdmApiClientDecoder;
import com.forgerock.sapi.gateway.dcr.service.idm.IdmApiClientService;
import com.forgerock.sapi.gateway.dcr.models.ApiClient;
import com.forgerock.sapi.gateway.jwks.ApiClientJwkSetService;
import com.forgerock.sapi.gateway.jwks.DefaultApiClientJwkSetService;
import com.forgerock.sapi.gateway.jwks.JwkSetService;
import com.forgerock.sapi.gateway.trusteddirectories.TrustedDirectory;
import com.forgerock.sapi.gateway.trusteddirectories.TrustedDirectoryService;

/**
 * Filter to validate that the client's MTLS transport certificate is valid when making a request to the Authorisation
 * Server's token endpoint.
 *
 * This is a specialised version of {@link TransportCertValidationFilter}, it does the same
 * validation, but has been adapted to do its validation on the response path. By deferring the validation to the response
 * path then we can be sure that we have an authenticated client.
 *
 * The access_token returned by the Authorisation Server is inspected to retrieve the client_id by using the
 * configurable accessTokenClientIdClaim. Once the client_id has been retrieved, it is used to look up the resources
 * needed to do validation, namely the {@link ApiClient} and their {@link org.forgerock.json.jose.jwk.JWKSet}.
 *
 * A configurable {@link CertificateRetriever} is used to retrieve the client's MTLS certificate. This is then validated
 * against the JWKSet for the ApiClient by using a {@link TransportCertValidator}.
 *
 * If the validation is successful the Authorisation Server Response is passed on along the filter chain. Otherwise,
 * an error response is returned with 400 BAD_REQUEST status.
 *
 * See {@link Heaplet} for filter configuration options.
 */
public class TokenEndpointTransportCertValidationFilter implements Filter {

    static final String DEFAULT_ACCESS_TOKEN_CLIENT_ID_CLAIM = "aud";

    private final Logger logger = LoggerFactory.getLogger(getClass());

    /**
     * Name of the access_token JWT claim containing the OAuth 2 client_id
     */
    private final String accessTokenClientIdClaim;

    private final JwtReconstruction jwtReconstruction = new JwtReconstruction();

    /**
     * Retrieves the client's mTLS certificate
     */
    private final CertificateRetriever certificateRetriever;

    /**
     * Service which retrieves {@link ApiClient} data
     */
    private final ApiClientService apiClientService;

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

    public TokenEndpointTransportCertValidationFilter(ApiClientService apiClientService, TrustedDirectoryService trustedDirectoryService,
                                                      ApiClientJwkSetService apiClientJwkSetService, CertificateRetriever certificateRetriever,
                                                      TransportCertValidator transportCertValidator, String accessTokenClientIdClaim) {
        Reject.ifNull(apiClientService, "apiClientService must be provided");
        Reject.ifNull(trustedDirectoryService, "trustedDirectoryService must be provided");
        Reject.ifNull(apiClientJwkSetService, "apiClientJwkSetService must be provided");
        Reject.ifNull(certificateRetriever, "certificateRetriever must be provided");
        Reject.ifNull(transportCertValidator, "transportCertValidator must be provided");
        Reject.ifBlank(accessTokenClientIdClaim, "accessTokenClientIdClaim must be provided");
        this.apiClientService = apiClientService;
        this.trustedDirectoryService = trustedDirectoryService;
        this.apiClientJwkSetService = apiClientJwkSetService;
        this.certificateRetriever = certificateRetriever;
        this.transportCertValidator = transportCertValidator;
        this.accessTokenClientIdClaim = accessTokenClientIdClaim;
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
                return response.getEntity()
                               .getJsonAsync()
                               .thenCatchAsync(ioe -> Promises.newExceptionPromise(new Exception("Failed to get response entity json", ioe)))
                               .then(this::getClientIdFromAccessToken)
                               .thenAsync(clientId -> getApiClient(context, clientId))
                               .thenAsync(validateApiClientTransportCert(clientCertificate, response),
                                          ex -> {
                                            // Top level exception handler
                                            logger.error("Failed to validate client mtls cert", ex);
                                            return Promises.newResultPromise(new Response(Status.INTERNAL_SERVER_ERROR));
                                          },
                                          rte -> {
                                              logger.error("Failed to validate client mtls cert",rte);
                                              return Promises.newResultPromise(new Response(Status.INTERNAL_SERVER_ERROR));
                                          });
            }
        });
    }

    private Promise<ApiClient, Exception> getApiClient(Context context, String clientId) {
        return apiClientService.getApiClient(clientId)
                               .thenOnResult(createAddApiClientToContextResultHandler(context, logger))
                               .thenCatchAsync(ae -> Promises.newExceptionPromise(new Exception("Failed to get ApiClient due to exception", ae)));
    }

    private AsyncFunction<ApiClient, Response, NeverThrowsException> validateApiClientTransportCert(X509Certificate clientCertificate,
                                                                                                    Response response) {

        return apiClient -> {
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
        };
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

    String getClientIdFromAccessToken(Object jsonValue) {
        final JsonValue json = JsonValue.json(jsonValue);
        final JsonValue accessToken = json.get("access_token");
        if (accessToken == null || accessToken.isNull()) {
            throw new IllegalStateException("Failed to get client_id: access_token is missing");
        }

        final SignedJwt accessTokenJwt = jwtReconstruction.reconstructJwt(accessToken.asString(), SignedJwt.class);
        final JsonValue clientId = accessTokenJwt.getClaimsSet().get(accessTokenClientIdClaim);
        if (clientId.isNull()) {
            throw new IllegalStateException("Failed to get client_id: access_token claims missing required '" + accessTokenClientIdClaim + "' claim");
        }
        return clientId.asString();
    }

    /**
     * Heaplet used to create {@link TransportCertValidationFilter} objects
     *
     * Mandatory fields:
     *
     *  - idmClientHandler: the clientHandler to use to call out to IDM (must be configured with the credentials required to query IDM)
     *  - idmManagedObjectsBaseUri: the base uri used to build the IDM query to get the apiClient, the client_id is expected
     *                            to be appended to this uri (and some query params).
     *  - trustedDirectoryService: the name of a {@link TrustedDirectoryService} object on the heap
     *  - jwkSetService: the name of the service (defined in config on the heap) that can obtain JWK Sets from a jwk set url
     *  - transportCertValidator: the name of a {@link TransportCertValidator} object on the heap to use to validate the certs
     *
     *  Optional config:
     * - certificateRetriever: a {@link CertificateRetriever} object heap reference used to retrieve the client's
     *                         certificate to validate.
     * - clientTlsCertHeader: (Deprecated - Use certificateRetriever config instead)
     *                        the name of the Request Header which contains the client's TLS cert
     *  - accessTokenClientIdClaim: the name of the claim in the access_token that contains the clientId. The clientId is then used to
     *                              fetch the ApiClient (and ApiClient's JWKS). Defaults to "aud"
     *
     * Example config:
     * {
     *           "comment": "Validate the MTLS transport cert",
     *           "name": "TokenEndpointTransportCertValidationFilter",
     *           "type": "TokenEndpointTransportCertValidationFilter",
     *           "config": {
     *             "clientTlsCertHeader": "ssl-client-cert",
     *             "idmClientHandler": "IDMClientHandler",
     *             "idmManagedObjectsBaseUri": "https://&{identity.platform.fqdn}/openidm/managed/apiClient",
     *             "trustedDirectoryService": "TrustedDirectoriesService",
     *             "jwkSetService": "OBJwkSetService",
     *             "transportCertValidator": "TransportCertValidator"
     *           }
     * }
     */
    public static class Heaplet extends GenericHeaplet {

        private final Logger logger = LoggerFactory.getLogger(getClass());

        @Override
        public Object create() throws HeapException {
            final Handler clientHandler = config.get("idmClientHandler").as(requiredHeapObject(heap, Handler.class));
            final Client httpClient = new Client(clientHandler);

            String idmManagedObjectsBaseUri = config.get("idmManagedObjectsBaseUri").required().asString();
            if (!idmManagedObjectsBaseUri.endsWith("/")) {
                idmManagedObjectsBaseUri = idmManagedObjectsBaseUri + '/';
            }

            final ApiClientService apiClientService = new IdmApiClientService(httpClient, idmManagedObjectsBaseUri, new IdmApiClientDecoder());

            final TrustedDirectoryService trustedDirectoryService = config.get("trustedDirectoryService")
                    .as(requiredHeapObject(heap, TrustedDirectoryService.class));


            final JwkSetService jwkSetService = config.get("jwkSetService").as(requiredHeapObject(heap, JwkSetService.class));
            final ApiClientJwkSetService apiClientJwkSetService = new DefaultApiClientJwkSetService(jwkSetService);

            final TransportCertValidator transportCertValidator = config.get("transportCertValidator").required()
                    .as(requiredHeapObject(heap, TransportCertValidator.class));

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
                        TokenEndpointTransportCertValidationFilter.class.getSimpleName(), CertificateRetriever.class);
                certificateRetriever = new HeaderCertificateRetriever(clientCertHeaderName);
            }

            final String accessTokenClientIdClaim =  config.get("accessTokenClientIdClaim")
                                                           .defaultTo(DEFAULT_ACCESS_TOKEN_CLIENT_ID_CLAIM).asString();

            return new TokenEndpointTransportCertValidationFilter(apiClientService, trustedDirectoryService,
                                                                  apiClientJwkSetService, certificateRetriever,
                                                                  transportCertValidator, accessTokenClientIdClaim);

        }
    }
}
