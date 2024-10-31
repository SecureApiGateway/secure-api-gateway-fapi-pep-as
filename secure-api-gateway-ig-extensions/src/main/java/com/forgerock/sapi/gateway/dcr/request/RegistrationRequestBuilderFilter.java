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
package com.forgerock.sapi.gateway.dcr.request;


import static com.forgerock.sapi.gateway.util.ContextUtils.REGISTRATION_REQUEST_KEY;
import static java.util.Objects.requireNonNull;
import static org.forgerock.json.JsonValueFunctions.setOf;
import static org.forgerock.openig.heap.Keys.CLOCK_HEAP_KEY;
import static org.forgerock.openig.util.JsonValues.javaDuration;
import static org.forgerock.openig.util.JsonValues.requiredHeapObject;

import java.time.Clock;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Stream;

import org.forgerock.http.Filter;
import org.forgerock.http.Handler;
import org.forgerock.http.protocol.Request;
import org.forgerock.http.protocol.Response;
import org.forgerock.http.protocol.Status;
import org.forgerock.json.jose.jws.JwsAlgorithm;
import org.forgerock.openig.fapi.dcr.RegistrationRequestFactory;
import org.forgerock.openig.fapi.jwks.JwkSetService;
import org.forgerock.openig.fapi.trusteddirectory.TrustedDirectoryService;
import org.forgerock.openig.heap.GenericHeaplet;
import org.forgerock.openig.heap.HeapException;
import org.forgerock.services.context.AttributesContext;
import org.forgerock.services.context.Context;
import org.forgerock.util.promise.NeverThrowsException;
import org.forgerock.util.promise.Promise;
import org.forgerock.util.promise.Promises;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.forgerock.sapi.gateway.common.jwt.JwtException;
import com.forgerock.sapi.gateway.common.rest.ContentTypeFormatterFactory;
import com.forgerock.sapi.gateway.common.rest.ContentTypeNegotiator;
import com.forgerock.sapi.gateway.common.rest.HttpMediaTypes;
import com.forgerock.sapi.gateway.dcr.common.ResponseFactory;
import com.forgerock.sapi.gateway.jws.JwtDecoder;

/**
 * A filter class that builds a {@code RegistrationRequest} object that contains a {@code SoftwareStatement} from
 * the body of a request to the /registration endpoint. If the {@code RegistationRequest} can successfully be built
 * then it is placed on the attributes context for use by subsequent filters
 */
public class RegistrationRequestBuilderFilter implements Filter {

    private static final Logger log = LoggerFactory.getLogger(RegistrationRequestBuilderFilter.class);
    private final RegistrationRequestEntitySupplier registrationEntitySupplier;
    private final RegistrationRequestFactory registrationRequestFactory;
    private final ResponseFactory responseFactory;
    private final JwtDecoder jwtDecoder;
    private final List<String> RESPONSE_MEDIA_TYPES = List.of(HttpMediaTypes.APPLICATION_JSON);
    private static final Set<String> VALIDATABLE_HTTP_REQUEST_METHODS = Set.of("POST", "PUT");

    /**
     * Constructor
     * @param registrationEntitySupplier - used by the filter to obtain the b64 url encoded registration request string
     *                                   from the request entity
     * @param responseFactory used to create a suitably formatted response should an error occur while processing the
     *                        registration request
     */
    public RegistrationRequestBuilderFilter(RegistrationRequestFactory registrationRequestFactory,
                                            RegistrationRequestEntitySupplier registrationEntitySupplier,
                                            JwtDecoder jwtDecoder,
                                            ResponseFactory responseFactory) {
        this.registrationRequestFactory = requireNonNull(registrationRequestFactory, "registrationRequestFactory must not be null");
        this.registrationEntitySupplier = requireNonNull(registrationEntitySupplier, "registrationEntitySupplier must not be null");
        this.jwtDecoder = requireNonNull(jwtDecoder, "jwtDecoder must not be null");
        this.responseFactory = requireNonNull(responseFactory, "responseFactory must not be null");
    }

    @Override
    public Promise<Response, NeverThrowsException> filter(Context context, Request request, Handler next) {
        if (!VALIDATABLE_HTTP_REQUEST_METHODS.contains(request.getMethod())) {
            return next.handle(context, request);
        }
        log.debug("Running RegistrationRequestEntityValidatorFilter");

        return this.registrationEntitySupplier.apply(context, request)
                                              .thenAsync(registrationRequestJwt -> {
                try {
                    return registrationRequestFactory.createRegistrationRequest(jwtDecoder.getSignedJwt(registrationRequestJwt))
                                                                           .thenAsync(registrationRequest -> {
                                                                               context.asContext(AttributesContext.class)
                                                                                      .getAttributes()
                                                                                      .put(REGISTRATION_REQUEST_KEY,
                                                                                           registrationRequest);

                                                                               log.info("Created context attribute " + REGISTRATION_REQUEST_KEY);
                                                                               return next.handle(context, request);
                                                                           }, e -> {
                                                                               log.error("Failed to create RegistrationRequest object from JWT", e);
                                                                               return Promises.newResultPromise(responseFactory.getResponse(RESPONSE_MEDIA_TYPES,
                                                                                                                                            Status.BAD_REQUEST,
                                                                                                                                            Map.of("error", e.getErrorCode().getCode(),
                                                                                                                                                   "error_description", e.getErrorDescription())));
                                                                           });
                } catch (JwtException e) {
                    log.info("Failed to understand the Registration Request body: {}", e.getMessage(), e);
                    return Promises.newResultPromise(responseFactory.getResponse(RESPONSE_MEDIA_TYPES,
                                                                                 Status.BAD_REQUEST,
                                                                                 Map.of("invalid_client_metadata", "Invalid registration request JWT")));
                }

        }, ioe -> {
            log.error("Failed to extract request JWT from HTTP Request", ioe);
            return Promises.newResultPromise(responseFactory.getInternalServerErrorResponse(request,
                                                                                            RESPONSE_MEDIA_TYPES));
        });
    }

    /**
     * Heaplet used to create {@link RegistrationRequestBuilderFilter} objects
     * <p>
     * Mandatory fields:
     * - trustedDirectoryService: the name of the service used to provide the trusted directory config
     * <p>
     * <pre>{@code
     * Example config:
     * {
     *      "name": "RegistrationRequestEntityValidationFilter",
     *      "type": "RegistrationRequestEntityValidatorFilter",
     *      "comment": "Pull the registration request from the entity and create a RegistrationRequest object context attribute",
     *      "config": {
     *        "trustedDirectoryService": "TrustedDirectoriesService"
     *      }
     *  }
     * }</pre>
     */
    public static class Heaplet extends GenericHeaplet {
        @Override
        public Object create() throws HeapException {
            final Clock clock = heap.get(CLOCK_HEAP_KEY, Clock.class);

            final Duration skewAllowance = config.get("skewAllowance")
                    .defaultTo("5 seconds")
                    .as(evaluatedWithHeapProperties())
                    .as(javaDuration());

            final JwkSetService jwkSetService = config.get("jwkSetService")
                    .as(requiredHeapObject(heap, JwkSetService.class));

            final TrustedDirectoryService trustedDirectoryService = config.get("trustedDirectoryService")
                    .as(requiredHeapObject(heap, TrustedDirectoryService.class));

            // Allow user to configure the algs supported
            // TODO need to ensure that the configuration contains only algs supported by the FAPI spec
            // currently this is PS256 and ES256
            final List<String> defaultFapiSigningAlgs = Stream.of(JwsAlgorithm.PS256, JwsAlgorithm.ES256)
                                            .map(JwsAlgorithm::getJwaAlgorithmName)
                                            .toList();
            final Set<JwsAlgorithm> supportedSigningAlgorithms = config.get("supportedSigningAlgorithms")
                                                                       .defaultTo(defaultFapiSigningAlgs)
                                                                       .as(setOf(value -> JwsAlgorithm.parseAlgorithm(value.asString())));

            final RegistrationRequestEntitySupplier registrationEntitySupplier
                    = new RegistrationRequestEntitySupplier();

            final JwtDecoder jwtDecoder = new JwtDecoder();

            final ContentTypeFormatterFactory contentTypeFormatterFactory = new ContentTypeFormatterFactory();
            final ContentTypeNegotiator contentTypeNegotiator =
                    new ContentTypeNegotiator(contentTypeFormatterFactory.getSupportedContentTypes());

            final ResponseFactory responseFactory = new ResponseFactory(contentTypeNegotiator,
                    contentTypeFormatterFactory);

            return new RegistrationRequestBuilderFilter(new RegistrationRequestFactory(jwkSetService,
                                                                                       trustedDirectoryService,
                                                                                       clock,
                                                                                       skewAllowance,
                                                                                       supportedSigningAlgorithms),
                                                        registrationEntitySupplier, jwtDecoder, responseFactory);
        }
    }
}
