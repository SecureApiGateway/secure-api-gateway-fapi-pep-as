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


import static java.util.Objects.requireNonNull;
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
import org.forgerock.services.context.AttributesContext;
import org.forgerock.services.context.Context;
import org.forgerock.util.promise.NeverThrowsException;
import org.forgerock.util.promise.Promise;
import org.forgerock.util.promise.Promises;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.forgerock.sapi.gateway.common.rest.ContentTypeFormatterFactory;
import com.forgerock.sapi.gateway.common.rest.ContentTypeNegotiator;
import com.forgerock.sapi.gateway.common.rest.HttpMediaTypes;
import com.forgerock.sapi.gateway.dcr.common.ResponseFactory;
import com.forgerock.sapi.gateway.dcr.common.exceptions.DCRException;
import com.forgerock.sapi.gateway.dcr.models.RegistrationRequest;
import com.forgerock.sapi.gateway.dcr.models.SoftwareStatement;
import com.forgerock.sapi.gateway.jws.JwtDecoder;
import com.forgerock.sapi.gateway.trusteddirectories.TrustedDirectoryService;

/**
 * A filter class that builds a {@code RegistrationRequest} object that contains a {@code SoftwareStatement} from
 * the body of a request to the /registration endpoint. If the {@code RegistationRequest} can successfully be built
 * then it is placed on the attributes context for use by subsequent filters
 */
public class RegistrationRequestBuilderFilter implements Filter {

    private static final Logger log = LoggerFactory.getLogger(RegistrationRequestBuilderFilter.class);
    private final RegistrationRequestEntitySupplier registrationEntitySupplier;
    private final ResponseFactory responseFactory;
    private final TrustedDirectoryService trustedDirectoryService;
    private final JwtDecoder jwtDecoder;
    private final List<String> RESPONSE_MEDIA_TYPES = List.of(HttpMediaTypes.APPLICATION_JSON);
    private static final Set<String> VALIDATABLE_HTTP_REQUEST_METHODS = Set.of("POST", "PUT");

    /**
     * Constructor
     * @param registrationEntitySupplier - used by the filter to obtain the b64 url encoded registration request string
     *                                   from the request entity
     * @param trustedDirectoryService used by the filter as part of decoding data from the SSA contained within the
     *                                registration request JWT
     * @param jwtDecoder used to decode registration request and SSA JWTs
     * @param responseFactory used to create a suitably formatted response should an error occur while processing the
     *                        registration request
     */
    public RegistrationRequestBuilderFilter(RegistrationRequestEntitySupplier registrationEntitySupplier,
                                            TrustedDirectoryService trustedDirectoryService,
                                            JwtDecoder jwtDecoder, ResponseFactory responseFactory) {
        this.registrationEntitySupplier = requireNonNull(registrationEntitySupplier, "registrationEntitySupplier must not be null");
        this.jwtDecoder = requireNonNull(jwtDecoder, "jwtDecoder must not be null");
        this.trustedDirectoryService = requireNonNull(trustedDirectoryService, "trustedDirectoryService must not be null");
        this.responseFactory = requireNonNull(responseFactory, "responseFactory must not be null");
    }

    @Override
    public Promise<Response, NeverThrowsException> filter(Context context, Request request, Handler next) {
        if (!VALIDATABLE_HTTP_REQUEST_METHODS.contains(request.getMethod())) {
            return next.handle(context, request);
        }
        log.debug("Running RegistrationRequestEntityValidatorFilter");
        try {
            final String b64EncodedRegistrationRequestEntity = this.registrationEntitySupplier.apply(context, request);
            final RegistrationRequest registrationRequest = new RegistrationRequest.Builder(
                    new SoftwareStatement.Builder(trustedDirectoryService, jwtDecoder), jwtDecoder)
                    .build(b64EncodedRegistrationRequestEntity);
            context.asContext(AttributesContext.class).getAttributes().put(RegistrationRequest.REGISTRATION_REQUEST_KEY,
                    registrationRequest);
            log.info("Created context attribute " + RegistrationRequest.REGISTRATION_REQUEST_KEY);
            return next.handle(context, request);
        } catch (DCRException exception){
            Response response = responseFactory.getResponse(RESPONSE_MEDIA_TYPES, Status.BAD_REQUEST,
                    exception.getErrorFields());
            log.info("Failed to understand the Registration Request body: {}", exception.getMessage(), exception);
            return Promises.newResultPromise(response);
        } catch (RuntimeException rte){
            log.warn("Caught runtime exception while applying RegistrationRequestEntityValidatorFilter", rte);
            Response internServerError = responseFactory.getInternalServerErrorResponse(request, RESPONSE_MEDIA_TYPES);
            return Promises.newResultPromise(internServerError);
        }
    }

    /**
     * Heaplet used to create {@link RegistrationRequestBuilderFilter} objects
     *
     * Mandatory fields:
     *  - trustedDirectoryService: the name of the service used to provide the trusted directory config
     *
     * Example config:
     * {
     *      "comment": "Pull the registration request from the entity and create a RegistrationRequest object context attribute",
     *      "name": "RegistrationRequestEntityValidationFilter",
     *      "type": "RegistrationRequestEntityValidatorFilter",
     *      "config": {
     *        "trustedDirectoryService": "TrustedDirectoriesService"
     *      }
     *  }
     */
    public static class Heaplet extends GenericHeaplet {
        @Override
        public Object create() throws HeapException {
            final TrustedDirectoryService trustedDirectoryService = config.get("trustedDirectoryService")
                    .as(requiredHeapObject(heap, TrustedDirectoryService.class));

            final RegistrationRequestEntitySupplier registrationEntitySupplier
                    = new RegistrationRequestEntitySupplier();

            final JwtDecoder jwtDecoder = new JwtDecoder();

            final ContentTypeFormatterFactory contentTypeFormatterFactory = new ContentTypeFormatterFactory();
            final ContentTypeNegotiator contentTypeNegotiator =
                    new ContentTypeNegotiator(contentTypeFormatterFactory.getSupportedContentTypes());

            final ResponseFactory responseFactory = new ResponseFactory(contentTypeNegotiator,
                    contentTypeFormatterFactory);

            return new RegistrationRequestBuilderFilter(registrationEntitySupplier,
                    trustedDirectoryService, jwtDecoder, responseFactory);
        }
    }
}
