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
package com.forgerock.sapi.gateway.fapi.v1.authorize;

import static com.forgerock.sapi.gateway.common.jwt.AuthorizeRequestParameterNames.CLIENT_ASSERTION;
import static com.forgerock.sapi.gateway.common.jwt.AuthorizeRequestParameterNames.CLIENT_ASSERTION_TYPE;
import static com.forgerock.sapi.gateway.common.jwt.AuthorizeRequestParameterNames.CLIENT_ID;
import static com.forgerock.sapi.gateway.common.jwt.AuthorizeRequestParameterNames.REQUEST;
import static com.forgerock.sapi.gateway.common.jwt.AuthorizeRequestParameterNames.REQUEST_URI;
import static com.forgerock.sapi.gateway.common.jwt.AuthorizeRequestParameterNames.RESPONSE_TYPE;
import static com.forgerock.sapi.gateway.common.jwt.AuthorizeRequestParameterNames.SCOPE;

import java.util.Arrays;
import java.util.List;
import java.util.Set;

import org.forgerock.http.Filter;
import org.forgerock.http.Handler;
import org.forgerock.http.protocol.Header;
import org.forgerock.http.protocol.Request;
import org.forgerock.http.protocol.Response;
import org.forgerock.http.protocol.Status;
import org.forgerock.json.jose.common.JwtReconstruction;
import org.forgerock.json.jose.jws.SignedJwt;
import org.forgerock.json.jose.jwt.JwtClaimsSet;
import org.forgerock.services.context.Context;
import org.forgerock.util.promise.NeverThrowsException;
import org.forgerock.util.promise.Promise;
import org.forgerock.util.promise.Promises;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.forgerock.sapi.gateway.common.error.OAuthErrorResponseFactory;
import com.forgerock.sapi.gateway.common.rest.ContentTypeFormatterFactory;
import com.forgerock.sapi.gateway.common.rest.HttpHeaderNames;

/**
 * Base class for validating that authorize requests are FAPI compliant.
 * <p>
 * This class can be extended to provide implementations which are specific to particular OAuth2.0 endpoints that
 * handle such requests, namely: /authorize and /par
 * <p>
 * Specs:
 * <ul>
 *     <li><a href="https://openid.net/specs/openid-financial-api-part-1-1_0.html#authorization-server">FAPI Part 1</a></li>
 *     <li><a href="https://openid.net/specs/openid-financial-api-part-2-1_0.html#authorization-server">FAPI Part 2</a></li>
 * </ul>
 */
public abstract class BaseFapiAuthorizeRequestValidationFilter implements Filter {
    private static final Set<String> RESPONSE_TYPE_CODE = Set.of("code");
    private static final Set<String> RESPONSE_TYPE_CODE_ID_TOKEN = Set.of("code", "id_token");
    private static final Set<String> VALID_HTTP_REQUEST_METHODS = Set.of("POST", "GET");
    private static final String REQUEST_JWT_PARAM_NAME = "request";

    protected final Logger logger = LoggerFactory.getLogger(getClass());

    // List of parameters to keep on the http request - all others will be removed and should be taken from the provided
    // JAR object
    private static final List<String> ALLOWED_HTML_PARAMETER_NAMES = List.of(CLIENT_ID, CLIENT_ASSERTION,
            CLIENT_ASSERTION_TYPE, REQUEST_URI, REQUEST, SCOPE, RESPONSE_TYPE);

    /**
     * Factory capable of producing OAuth2.0 compliant HTTP Responses for error conditions.
     */
    protected final OAuthErrorResponseFactory errorResponseFactory = new OAuthErrorResponseFactory(new ContentTypeFormatterFactory());

    public Promise<Response, NeverThrowsException> filter(Context context, Request request, Handler next) {
        if (!VALID_HTTP_REQUEST_METHODS.contains(request.getMethod())) {
            return Promises.newResultPromise(new Response(Status.METHOD_NOT_ALLOWED));
        }

        final Header acceptHeader = request.getHeaders().get(HttpHeaderNames.ACCEPT);
        return getRequestJwtClaimSet(request).thenAsync(requestJwtClaimSet -> {
            if (requestJwtClaimSet == null) {
                final String errorDescription = "Request must have a 'request' parameter the value of which must be a signed jwt";
                return Promises.newResultPromise(errorResponseFactory.invalidRequestErrorResponse(acceptHeader, errorDescription));
            }

            // Spec covering the necessity of these fields to exist in the authorization request:
            // scope - The FAPI Advanced part 1 spec, section 5.2.2.1 states that
            //   "if it is desired to provide the  authenticated user's identifier to the client
            //   in the token response, the authorization server:
            //   1. shall support the authentication request as in Section 3.1.2.1 of OIDC
            //   (see https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest)
            //
            // The OIDC spec states that scope, response_type, client_id and redirect are required.
            // -------------------------
            // FAPI Advanced Part 1, part 5.2.2.3
            //   "1. shall require the nonce parameter defined in Section 3.1.2.1 of OIDC in the authentication request"
            // (see https://openid.net/specs/openid-financial-api-part-1-1_0.html#client-requesting-openid-scope)
            for (String requiredClaim : getRequiredRequestJwtClaims()) {
                if (!requestJwtHasClaim(requiredClaim, requestJwtClaimSet)) {
                    String errorDescription = "Request JWT must have a '" + requiredClaim + "' claim";
                    return Promises.newResultPromise(errorResponseFactory.invalidRequestErrorResponse(acceptHeader, errorDescription));
                }
            }

            final Response responseTypeValidationErrorResponse = validateResponseType(acceptHeader, requestJwtClaimSet);
            if (responseTypeValidationErrorResponse != null) {
                return Promises.newResultPromise(responseTypeValidationErrorResponse);
            }

            final Response endpointSpecificClaimsChecksResponse = checkEndpointSpecificClaims(acceptHeader,
                    requestJwtClaimSet);
            if(endpointSpecificClaimsChecksResponse != null){
                return Promises.newResultPromise(endpointSpecificClaimsChecksResponse);
            }

            // Remove parameters that should be ignored from the http request - parameters should only be read from
            // the JAR object
            return removeParamsFromRequest(request)
                    .thenAsync(noResult -> {
                        logger.info("Authorize request is FAPI compliant");
                        return next.handle(context, request);
                    });
        });
    }



    /**
     * Applies validation logic relating to the response_type
     * <p>
     * https://openid.net/specs/openid-financial-api-part-2-1_0.html#authorization-server specifies:
     * the authorization server shall require
     * <ol>
     *     <li>the response_type value code id_token, or</li>
     *     <li>the response_type value code in conjunction with the response_mode value jwt</li>
     * </ol>
     * <p>
     * https://openid.net/specs/openid-financial-api-part-2-1_0.html#id-token-as-detached-signature-1 specifies:
     * In addition, if the response_type value code id_token is used, the client shall include the value openid
     * into the scope parameter in order to activate OIDC support;
     */
    Response validateResponseType(Header acceptHeader, JwtClaimsSet requestJwtClaimSet) {
        final String responseTypeStr = requestJwtClaimSet.get("response_type").asString();
        final Set<String> responseType = Set.of(responseTypeStr.split(" "));
        if (responseType.equals(RESPONSE_TYPE_CODE)) {
            return validateResponseTypeCode(acceptHeader, requestJwtClaimSet);
        } else if (responseType.equals(RESPONSE_TYPE_CODE_ID_TOKEN)) {
            return validateResponseTypeCodeIdToken(acceptHeader, requestJwtClaimSet);
        } else {
            return errorResponseFactory.invalidRequestErrorResponse(acceptHeader, "response_type not supported, must be one of: \"code\", \"code id_token\"");
        }
    }

    private Response validateResponseTypeCode(Header acceptHeader, JwtClaimsSet requestJwtClaimSet) {
        final String responseMode = requestJwtClaimSet.get("response_mode").asString();
        if (responseMode == null) {
            return errorResponseFactory.invalidRequestErrorResponse(acceptHeader,
                    "response_mode must be specified when response_type is: \"code\"");
        }
        // Check if response_mode is one of: jwt, query.jwt, fragment.jwt or form_post.jwt
        if (!responseMode.contains("jwt")) {
            return errorResponseFactory.invalidRequestErrorResponse(acceptHeader,"response_mode must be: \"jwt\" when response_type is: \"code\"");
        }
        return null;
    }

    private Response validateResponseTypeCodeIdToken(Header acceptHeader, JwtClaimsSet requestJwtClaimSet) {
        final String scopeClaim = requestJwtClaimSet.get("scope").asString();
        final List<String> scopes = Arrays.asList(scopeClaim.split(" "));
        if (!scopes.contains("openid")) {
            return errorResponseFactory.invalidRequestErrorResponse(acceptHeader,
                    "request object must include openid as one of the requested scopes when response_type is: \"code id_token\"");
        }
        return null;
    }

    protected Promise<JwtClaimsSet, NeverThrowsException> getRequestJwtClaimSet(Request request) {
        return getParamFromRequest(request, REQUEST_JWT_PARAM_NAME).then(requestJwtString -> {
            if (requestJwtString == null) {
                logger.info("authorize request must have a request JWT parameter");
                return null;
            }
            try {
                SignedJwt jwt = new JwtReconstruction().reconstructJwt(requestJwtString, SignedJwt.class);
                return jwt.getClaimsSet();
            } catch (RuntimeException ex) {
                logger.info("BAD_REQUEST: Could not parse request JWT string", ex);
                return null;
            }
        });
    }

    /**
     * Because FAPI requires the use of a JWT-Secured Authorized Request (JAR) in accordance with RFC 9101. That rfc
     * states in
     * <a href="https://www.rfc-editor.org/rfc/rfc9101.html#name-request-parameter-assembly-">section 6.3 of the RFC"
     * </a> that;
     *
     * <pre>  The authorization server MUST extract the set of authorization request parameters from the Request Object
     * value. The authorization server MUST only use the parameters in the Request Object, even if the same parameter is
     * provided in the query parameter. The client ID values in the client_id request parameter and in the Request
     * Object client_id claim MUST be identical. The authorization server then validates the request, as specified in
     * OAuth 2.0 [RFC6749].
     *
     * If the Client ID check or the request validation fails, then the authorization server MUST return an error to
     * the client in response to the authorization request, as specified in Section 5.2 of [RFC6749] (OAuth 2.0). </pre>
     *
     * This means that any parameters supplied with the request (both /par and /authorize requests) should ignore any
     * parameters provided with the request, and use only the parameters supplied in the JAR object. The exceptions to
     * the rule are those elements of the request required for the client authorization method, e.g. {@code client_id}
     * for {@code tls_client_auth} type requests and {@code client_assertion} and {@code client_assertion_type} for
     * {@code private_key_jwt} requests.
     *
     * <p>This method removes all parameters except the following;
     *   <ul>
     *       <li>{@code client_id}</li>
     *       <li>{@code client_assertion}</li>
     *       <li>{@code client_assertion_type}</li>
     *       <li>{@code request_uri}</li>
     *       <li>{@code request}</li>
     *   </ul>
     * </p>
     *
     * <p>Due to issues in AM, this method will also leave the following parameters, although it shouldn't have to;
     * <ul>
     *     <li>{@code scope}</li>
     *     <li>{@code response_type}</li>
     * </ul>
     * </p>
     *
     *
     * @param request the request from which all non authorization method parameters are to be removed
     * @return a Promise that will resolve when the method has completed
     */
    protected Promise<Void, NeverThrowsException> removeParamsFromRequest(Request request) {
        return removeNonMatchingParamsFromRequest(request, ALLOWED_HTML_PARAMETER_NAMES).thenOnResult((removedParams)->{
            logger.info("Removed {} params from the request", removedParams.size());
        }).thenDiscardResult();
    }

    /**
     * Retrieves a parameter from the HTTP Request.
     *
     * @param request   Request the HTTP Request to retrieve the parameter from
     * @param paramName String the name of the parameter
     * @return Promise<String, NeverThrowsException> which returns the param value as a String or a null if the param
     * does not exist or fails to be retrieved due to an exception.
     */
    protected abstract Promise<String, NeverThrowsException> getParamFromRequest(Request request, String paramName);


    /**
     * Returns a list of the required claims that must be present in the request JWT
     * @return String<List> which contains the list of claims
     */
    protected abstract List<String> getRequiredRequestJwtClaims();

    /**
     * Check specific claim combinations specific to the request type. Handled by the child implementations
     * @param acceptHeader - used to determine the media type of the response
     * @param requestJwtClaimSet - the claims found in the JAR object of the request
     * @return Response - null if no checks failed, or contains an error response if a check failed.
     */
    protected abstract Response checkEndpointSpecificClaims(Header acceptHeader, JwtClaimsSet requestJwtClaimSet);

    /**
     * Checks if the claim exists in the requestJwtClaimSet
     */
    protected boolean requestJwtHasClaim(String claimName, JwtClaimsSet requestJwtClaims) {
        return requestJwtClaims.getClaim(claimName) != null;
    }

    /**
     * Implementation which removes parameter values that don't match an entry in paramNamesToKeep from the
     * Request's Parameters
     * @param request the request from which to remove the HTTP Request's query parameters
     * @param paramNamesToKeep the list of HTTP Request parameters to keep
     * @return Promise<List<String>, NeverThrowsException> which returns the list of parameter names that were removed
     */
    protected abstract Promise<List<String>, NeverThrowsException> removeNonMatchingParamsFromRequest(Request request,
            List<String> paramNamesToKeep);

}
