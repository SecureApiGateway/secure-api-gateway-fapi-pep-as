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
package com.forgerock.sapi.gateway.dcr.sigvalidation;

import static org.forgerock.openig.util.JsonValues.requiredHeapObject;

import java.util.List;
import java.util.Set;

import org.forgerock.http.Filter;
import org.forgerock.http.Handler;
import org.forgerock.http.protocol.Request;
import org.forgerock.http.protocol.Response;
import org.forgerock.http.protocol.Status;
import org.forgerock.openig.heap.GenericHeaplet;
import org.forgerock.openig.heap.HeapException;
import org.forgerock.services.context.Context;
import org.forgerock.util.Reject;
import org.forgerock.util.promise.NeverThrowsException;
import org.forgerock.util.promise.Promise;
import org.forgerock.util.promise.Promises;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.forgerock.sapi.gateway.common.rest.ContentTypeFormatterFactory;
import com.forgerock.sapi.gateway.common.rest.ContentTypeNegotiator;
import com.forgerock.sapi.gateway.common.rest.HttpMediaTypes;
import com.forgerock.sapi.gateway.dcr.common.ResponseFactory;
import com.forgerock.sapi.gateway.dcr.models.RegistrationRequest;
import com.forgerock.sapi.gateway.jwks.JwkSetService;
import com.forgerock.sapi.gateway.jws.JwtSignatureValidator;
import com.forgerock.sapi.gateway.util.ContextUtils;

public class RegistrationRequestJwtSignatureValidationFilter implements Filter {

    private static final Logger log = LoggerFactory.getLogger(RegistrationRequestJwtSignatureValidationFilter.class);
    /**
     * The HTTP methods to apply validation to.
     * POST is used to create new OAuth2 client's and PUT updates existing OAuth2 clients, both of these types of
     * request must be validated.
     * DCR API also supports GET and DELETE, there is no validation to apply here so requests with these methods should
     * be passed on down the chain.
     */
    private static final Set<String> VALIDATABLE_HTTP_REQUEST_METHODS = Set.of("POST", "PUT");

    private final SoftwareStatementAssertionSignatureValidatorService ssaValidator;
    private final RegistrationRequestJwtSignatureValidationService registrationRequestJwtValidator;
    private final ResponseFactory responseFactory;
    
    private final List<String> RESPONSE_MEDIA_TYPES = List.of(HttpMediaTypes.APPLICATION_JSON);

    /**
     * Constructor
     * @param ssaValidator a service used to validate the SSA signature
     * @param registrationRequestJwtValidator used to validate the registration request jwt signature
     * @param responseFactory used to obtain an error {@code Response} from a DCRException
     */
    RegistrationRequestJwtSignatureValidationFilter(
            SoftwareStatementAssertionSignatureValidatorService ssaValidator,
            RegistrationRequestJwtSignatureValidationService registrationRequestJwtValidator,
            ResponseFactory responseFactory) {
        Reject.ifNull(ssaValidator, "ssaValidator must be provided");
        Reject.ifNull(registrationRequestJwtValidator, "registrationRequestJwtValidator must be provided");
        Reject.ifNull(responseFactory, "responseFactory must be supplied");

        this.ssaValidator = ssaValidator;
        this.registrationRequestJwtValidator = registrationRequestJwtValidator;
        this.responseFactory = responseFactory;

        log.debug("RequestAndSsaSignatureValidationFilter constructed");
    }

    @Override
    public Promise<Response, NeverThrowsException> filter(Context context, Request request, Handler next) {
        log.debug("Filtering out invalid signatures of registration request and ssa jwts");
        if (!VALIDATABLE_HTTP_REQUEST_METHODS.contains(request.getMethod())) {
            return next.handle(context, request);
        }

        try {
            final RegistrationRequest registrationRequest = ContextUtils.getRequiredAttributeAsType(context,
                    RegistrationRequest.REGISTRATION_REQUEST_KEY, RegistrationRequest.class);
            log.debug("Performing JWT signature validation on registration request '{}'", registrationRequest);

            Promise<Response, DCRSignatureValidationException> ssaValidationPromise =
                    ssaValidator.validateJwtSignature(registrationRequest.getSoftwareStatement());

            return ssaValidationPromise.thenAsync( response ->
                registrationRequestJwtValidator.validateJwtSignature(registrationRequest).thenAsync(
                    regRequestValidationResponse -> {
                        if (regRequestValidationResponse.getStatus() != Status.OK) {
                            log.info("Response from validation is not OK as expected. Response: {}", regRequestValidationResponse);
                            return Promises.newResultPromise(response);
                        }
                        registrationRequest.setSignatureHasBeenValidated(true);
                        log.debug("Registration Request and embedded SSA both have valid signatures");
                        return next.handle(context, request);
                    }, ex -> {
                        log.info("Registration Request validation failed: {}", ex.getMessage(), ex);
                        Response badRequest = responseFactory.getResponse(RESPONSE_MEDIA_TYPES, Status.BAD_REQUEST,
                                                                          ex.getErrorFields());
                        return Promises.newResultPromise(badRequest);
                    }, rte -> {
                        log.info("Runtime Exception occurred while validating the Registration Response Jwt signature",
                                 rte);
                        Response internServerError = responseFactory.getInternalServerErrorResponse(request,
                                RESPONSE_MEDIA_TYPES);
                        return Promises.newResultPromise(internServerError);
                    }
                ), ex -> {
                    log.info("Software Statement validation failed" , ex);
                    Response badRequest = responseFactory.getResponse(RESPONSE_MEDIA_TYPES, Status.BAD_REQUEST,
                                                                      ex.getErrorFields());
                    return Promises.newResultPromise(badRequest);
                }, rte -> {
                    log.error("Runtime Error while validating Registration Request", rte);
                    return Promises.newResultPromise(responseFactory.getInternalServerErrorResponse(request, RESPONSE_MEDIA_TYPES));
                });
        } catch (RuntimeException rte){
            log.error("Runtime Error occurred in RequestAndSsaSignatureValidationFilter", rte);
            return Promises.newResultPromise(new Response(Status.INTERNAL_SERVER_ERROR));
        }
    }

    /**
     * Heaplet used to create {@link RegistrationRequestJwtSignatureValidationFilter} objects
     *
     * Mandatory fields:
     *  - jwkSetService: the name of the service (defined in config on the heap) that can obtain JWK Sets from a jwk
     *                   set url
     *  - jwtSignatureValidator: the name of the service that the filter should use to validate a jwt signature against
     *                           a JWK Set
     *
     * Example config:
     * {
     *   "comment": "Validate the signature of the SSA and the request Jwt",
     *   "name": "RequestAndSsaSignatureValidationFilter",
     *   "type": "RequestAndSsaSignatureValidationFilter",
     *   "config": {
     *     "jwkSetService": "OBJwkSetService",
     *     "jwtSignatureValidator": "RsaJwtSignatureValidator"
     *   }
     * }
     */
    public static class Heaplet extends GenericHeaplet {
        @Override
        public Object create() throws HeapException {
            final JwkSetService jwtSetService = config.get("jwkSetService")
                    .as(requiredHeapObject(heap, JwkSetService.class));

            final JwtSignatureValidator jwtSignatureValidator = config.get("jwtSignatureValidator")
                    .as(requiredHeapObject(heap, JwtSignatureValidator.class));

            final SoftwareStatementAssertionSignatureValidatorService ssaSignatureValidator
                    = new SoftwareStatementAssertionSignatureValidatorService(jwtSetService, jwtSignatureValidator);

            final JwksSupplierEmbeddedJwks regRequestJwksValidator = new JwksSupplierEmbeddedJwks();

            final JwksSupplierJwksUri regRequestJwksUriValidator = new JwksSupplierJwksUri(jwtSetService);

            final RegistrationRequestJwtSignatureValidationService registrationRequestValidator =
                    new RegistrationRequestJwtSignatureValidationService(
                            regRequestJwksValidator, regRequestJwksUriValidator, jwtSignatureValidator);
            final ContentTypeFormatterFactory contentTypeFormatterFactory = new ContentTypeFormatterFactory();
            final ContentTypeNegotiator contentTypeNegotiator =
                    new ContentTypeNegotiator(contentTypeFormatterFactory.getSupportedContentTypes());

            final ResponseFactory responseFactory = new ResponseFactory(contentTypeNegotiator,
                    contentTypeFormatterFactory);

            return new RegistrationRequestJwtSignatureValidationFilter(
                    ssaSignatureValidator, registrationRequestValidator, responseFactory);
        }
    }

}
