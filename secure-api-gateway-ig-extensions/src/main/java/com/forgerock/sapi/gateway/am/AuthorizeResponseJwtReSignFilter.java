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
package com.forgerock.sapi.gateway.am;

import static org.forgerock.http.protocol.Responses.newInternalServerError;
import static org.forgerock.openig.util.JsonValues.requiredHeapObject;
import static org.forgerock.util.promise.Promises.newResultPromise;

import java.net.URISyntaxException;
import java.security.SignatureException;
import java.util.List;
import java.util.Optional;

import org.forgerock.http.Filter;
import org.forgerock.http.Handler;
import org.forgerock.http.MutableUri;
import org.forgerock.http.header.LocationHeader;
import org.forgerock.http.protocol.Form;
import org.forgerock.http.protocol.Request;
import org.forgerock.http.protocol.Response;
import org.forgerock.http.protocol.Status;
import org.forgerock.json.jose.common.JwtReconstruction;
import org.forgerock.json.jose.jws.SignedJwt;
import org.forgerock.openig.heap.GenericHeaplet;
import org.forgerock.openig.heap.HeapException;
import org.forgerock.services.context.Context;
import org.forgerock.util.AsyncFunction;
import org.forgerock.util.Reject;
import org.forgerock.util.annotations.VisibleForTesting;
import org.forgerock.util.promise.NeverThrowsException;
import org.forgerock.util.promise.Promise;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * This filter aims to fix an issue in AM relating to signing of the JWTs returned by the /authorize endpoint.
 * The issue is that the wrong kid is used by AM, see {@link JwtReSigner} for further details.
 * <p>
 * The /authorize endpoint may produce JWTs in the following ways, all of which will be re-signed by this filter.
 * <ul>
 *     <li>id_token param in redirect response location header URI</li>
 *     <li>
 *         When using JARM, in the response JWT param in the redirect response location header URI
 *     <ul>
 *         <li>Optionally - within the response JWT an id_token JWT may be nested</li>
 *     </ul>
 *     </li>
 * </ul>
 */
public class AuthorizeResponseJwtReSignFilter implements Filter {

    private static final String ID_TOKEN_FIELD_NAME = "id_token";

    private static final String RESPONSE_JWT_PARAM_NAME = "response";

    private static final Logger LOGGER = LoggerFactory.getLogger(AuthorizeResponseJwtReSignFilter.class);

    /**
     * Function which produces a {@link Response} to return when a {@link SignatureException} is handled.
     * <p>
     * This handler logs the exception passed and returns an HTTP 500 Internal Server Error Response, this type of
     * Response is being used as there is no action the client can take to fix them, the issue will be due to
     * misconfiguration or a change in AM behaviour.
     */
    private static final org.forgerock.util.Function<SignatureException, Response, NeverThrowsException> signatureExceptionResponseHandler = ex -> {
        LOGGER.error("Failed to re-sign JWT due to exception", ex);
        return newInternalServerError();
    };
    /**
     * AsyncFunction which produces a {@link Response} to return when a {@link SignatureException} is handled.
     * Wraps signatureExceptionResponseHandler in a Promise for use in async Promise chaining.
     */
    private static final AsyncFunction<SignatureException, Response, NeverThrowsException> asyncSignatureExceptionResponseHandler = ex -> newResultPromise(signatureExceptionResponseHandler.apply(ex));

    /**
     * Takes a JWT as input, verifies the signature and re-signs it with the configured private key.
     */
    private final JwtReSigner jwtReSigner;
    private final JwtReconstruction jwtReconstruction = new JwtReconstruction();

    public AuthorizeResponseJwtReSignFilter(JwtReSigner jwtReSigner) {
        Reject.ifNull(jwtReSigner, "jwtReSigner must be supplied");
        this.jwtReSigner = jwtReSigner;
    }

    @Override
    public Promise<Response, NeverThrowsException> filter(Context context, Request request, Handler handler) {
        return handler.handle(context, request).thenAsync(response -> {
            // Allow AM errors to pass through
            if (!response.getStatus().isSuccessful() && !response.getStatus().isRedirection()) {
                return newResultPromise(response);
            } else {
                final Optional<MutableUri> optionalLocationUri = getLocationHeader(response);
                if (optionalLocationUri.isEmpty()) {
                    LOGGER.debug("No location header found, skipping");
                    return newResultPromise(response);
                }
                final MutableUri locationUri = optionalLocationUri.get();
                if (isJwtResponseMode(request)) {
                    return handleJwtResponseMode(locationUri, response);
                } else {
                    return handlePlainResponseMode(locationUri, response);
                }
            }
        });
    }

    /**
     * handles re-signing data for the plain (default) response mode i.e. not JARM.
     *
     * @param locationUri the URI from the Location header in the redirect response which contains the JWT to re-sign
     * @param response    the Response to update
     * @return Promise with the updated Response or an HTTP 500 Internal Server Error Response if an error occurs
     */
    private Promise<Response, NeverThrowsException> handlePlainResponseMode(MutableUri locationUri, Response response) {
        LOGGER.debug("handling plain response_mode re-signing");
        final Form formParams = getFormParams(locationUri);
        final String idTokenJwtString = formParams.getFirst(ID_TOKEN_FIELD_NAME);
        // May not be present on the first redirect call if the user
        if (idTokenJwtString == null) {
            LOGGER.debug("No id_token found in response, doing nothing.");
            return newResultPromise(response);
        }
        return jwtReSigner.reSignJwt(idTokenJwtString).then(reSignedIdToken -> {
            LOGGER.debug("Successfully re-signed id_token: {}", reSignedIdToken);
            formParams.replace(ID_TOKEN_FIELD_NAME, List.of(reSignedIdToken));
            updateResponseLocationHeader(locationUri, response, formParams.toQueryString());
            return response;
        }, signatureExceptionResponseHandler);
    }

    /**
     * handles re-signing data for JWT response mode aka JARM.
     *
     * @param locationUri the URI from the Location header in the redirect response which contains the JWT to re-sign
     * @param response    the Response to update
     * @return Promise with the updated Response or an HTTP 500 Internal Server Error Response if an error occurs
     */
    private Promise<Response, NeverThrowsException> handleJwtResponseMode(MutableUri locationUri, Response response) {
        LOGGER.debug("handling jwt response_mode re-signing");
        final Form formParams = getFormParams(locationUri);
        final String responseJwtString = formParams.getFirst(RESPONSE_JWT_PARAM_NAME);
        if (responseJwtString == null) {
            LOGGER.debug("No response JWT found in response, doing nothing.");
            return newResultPromise(response);
        }
        final SignedJwt originalResponseJwt = jwtReconstruction.reconstructJwt(responseJwtString, SignedJwt.class);
        final String idTokenClaim = originalResponseJwt.getClaimsSet().getClaim(ID_TOKEN_FIELD_NAME, String.class);
        final Promise<SignedJwt, SignatureException> responseJwtWithReSignedContentsPromise;
        if (idTokenClaim != null) {
            LOGGER.debug("Found id_token in response JWT");
            // response JWT contains an id_token JWT, re-sign the inner id_token JWT first
            responseJwtWithReSignedContentsPromise = jwtReSigner.reSignJwt(idTokenClaim).then(reSignedIdToken -> {
                LOGGER.debug("Successfully re-signed id_token: {} in response JWT", reSignedIdToken);
                originalResponseJwt.getClaimsSet().setClaim(ID_TOKEN_FIELD_NAME, reSignedIdToken);
                return originalResponseJwt;
            });
        } else {
            // nothing inside the response JWT needs re-signing
            responseJwtWithReSignedContentsPromise = newResultPromise(originalResponseJwt);
        }

        // re-sign the response JWT
        return responseJwtWithReSignedContentsPromise.thenAsync(
                responseJwtWithReSignedContents -> jwtReSigner.reSignJwt(responseJwtWithReSignedContents)
                        .then(reSignedJwt -> {
                                final String reSignedJwtStr = reSignedJwt.build();
                                LOGGER.debug("Successfully re-signed response JWT: {}", reSignedJwtStr);

                                formParams.replace(RESPONSE_JWT_PARAM_NAME, List.of(reSignedJwtStr));
                                return updateResponseLocationHeader(locationUri, response, formParams.toQueryString());
                        }, signatureExceptionResponseHandler),
                asyncSignatureExceptionResponseHandler);
    }

    private static Form getFormParams(MutableUri locationUri) {
        final String fragmentOrQuery = isFragmentResponse(locationUri) ? locationUri.getFragment() : locationUri.getQuery();
        // both fragments and query strings in this OAuth2.0 context are represented as application/x-www-form-urlencoded values
        return new Form().fromQueryString(fragmentOrQuery);
    }

    private static Response updateResponseLocationHeader(MutableUri locationUri, Response response, String fragmentOrQueryString) {
        try {
            if (isFragmentResponse(locationUri)) {
                locationUri.setFragment(fragmentOrQueryString);
            } else {
                locationUri.setQuery(fragmentOrQueryString);
            }
        } catch (URISyntaxException ex) {
            LOGGER.error("Failed to rebuild locationUri using fragmentOrQuery: {}", fragmentOrQueryString, ex);
            return new Response(Status.INTERNAL_SERVER_ERROR);
        }
        response.getHeaders().replace(LocationHeader.NAME, locationUri.toString());
        return response;
    }

    /**
     * Determines whether jwt response_mode is specified in the {@link Request} object's request JWT URI Query Param
     *
     * @param request the {@link Request} to inspect
     * @return true if the response_mode is set to jwt or false if it is not specified or has another value.
     */
    @VisibleForTesting
    boolean isJwtResponseMode(Request request) {
        final String requestJwtString = request.getQueryParams().getFirst("request");
        if (requestJwtString == null) {
            return false;
        }
        final SignedJwt requestJwt = jwtReconstruction.reconstructJwt(requestJwtString, SignedJwt.class);
        final String responseMode = requestJwt.getClaimsSet().getClaim("response_mode", String.class);
        return responseMode != null && responseMode.contains("jwt");
    }

    private static boolean isFragmentResponse(MutableUri locationUri) {
        return locationUri.getFragment() != null;
    }

    private static Optional<MutableUri> getLocationHeader(Response response) {
        final String locationHeader = response.getHeaders().getFirst(LocationHeader.NAME);
        if (locationHeader == null) {
            return Optional.empty();
        }
        try {
            return Optional.of(MutableUri.uri(locationHeader));
        } catch (URISyntaxException e) {
            LOGGER.debug("Failed to parse URI in location header", e);
            return Optional.empty();
        }
    }

    /**
     * Heaplet which creates {@link AuthorizeResponseJwtReSignFilter} objects.
     * <p>
     * Configuration:
     * <ul>
     *     <li>jwtReSigner name of a {@link JwtReSigner} available on the heap, used to validate in the incoming JWT
     *         and produce the new JWT signed with the correct key and keyId.</li>
     * </ul>
     * <p>
     * <pre>{@code
     * Example config:
     * {
     *   "name": "AuthorizeResponseJwtResignFilter",
     *   "type": "AuthorizeResponseJwtResignFilter",
     *   "comment": "Re-sign the id_token returned by AM to fix OB keyId issue",
     *   "config": {
     *     "jwtReSigner": "jwtReSigner"
     *   }
     * }
     * }</pre>
     */
    public static class Heaplet extends GenericHeaplet {

        @Override
        public Object create() throws HeapException {
            final JwtReSigner jwtReSigner = config.get("jwtReSigner").as(requiredHeapObject(heap, JwtReSigner.class));
            return new AuthorizeResponseJwtReSignFilter(jwtReSigner);
        }
    }
}
