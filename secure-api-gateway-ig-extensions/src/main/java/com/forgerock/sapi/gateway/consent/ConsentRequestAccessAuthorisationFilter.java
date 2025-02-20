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
package com.forgerock.sapi.gateway.consent;

import java.util.Map;

import org.forgerock.http.Filter;
import org.forgerock.http.Handler;
import org.forgerock.http.protocol.Request;
import org.forgerock.http.protocol.Response;
import org.forgerock.http.protocol.Status;
import org.forgerock.openig.filter.jwt.JwtValidationContext;
import org.forgerock.openig.heap.GenericHeaplet;
import org.forgerock.openig.heap.HeapException;
import org.forgerock.openig.openam.SsoTokenContext;
import org.forgerock.services.context.Context;
import org.forgerock.util.Reject;
import org.forgerock.util.promise.NeverThrowsException;
import org.forgerock.util.promise.Promise;
import org.forgerock.util.promise.Promises;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Filter that protects access to a consent request by validating that an end user browser session belongs to the
 * same user that is specified in the signed consent request JWT (sent from AM). This can be used in filter chains
 * which protect Remote Consent flows.
 * <p>
 * This filter depends on the {@link SsoTokenContext} and {@link JwtValidationContext}, therefore it must be installed
 * after filters which add these contexts.
 * <p>
 * The {@link SsoTokenContext} is used to determine the user that is logged in, by inspecting the session "uid".
 * <p>
 * The {@link JwtValidationContext} is used to determine the user that owns the consent request, by inspecting the
 * "username" claim. It is assumed that consent request JWT has been fully validated, that the signature has been verified and that
 * the "exp", "iat", "iss" and "aud" claims have all been validated.
 * <p>
 * If the SSO user matches the consent user then this filter passes the request on to the next handler in the chain.
 * Otherwise, this filter responds with HTTP 401.
 * <p>
 * If any exceptions are raised when extracting the user data from the contexts then this filter responds with HTTP 500.
 * This is because an exception indicates either an error in the IG configuration or AM configuration; there is no action
 * that an end user can take to resolve the issue.
 */
public class ConsentRequestAccessAuthorisationFilter implements Filter {

    private static final Logger LOGGER = LoggerFactory.getLogger(ConsentRequestAccessAuthorisationFilter.class);
    static final String DEFAULT_CONSENT_REQUEST_USER_ID_CLAIM = "username";
    static final String DEFAULT_SSO_TOKEN_USER_ID_KEY = "uid";

    private final String consentRequestUserIdClaim;
    private final String ssoTokenUserIdKey;

    /**
     * Handles exceptions raised by the business logic of this filter and converts them into HTTP Response objects
     */
    @FunctionalInterface
    interface ExceptionHandler {
        Response onException(Context context, Exception ex);
    }

    /**
     * @return ExceptionHandler instance which logs the exception and returns a HTTP 500 response. All exceptions in
     * this filter are unexpected, there is no action that the end user can take to resolve issues. If an exception
     * occurs then it indicates a misconfiguration in a ForgeRock application.
     */
    static ExceptionHandler createDefaultExceptionHandler() {
        return (ctxt, ex) -> {
            LOGGER.warn("Failed to get userId data required to do authorisation check", ex);
            return new Response(Status.INTERNAL_SERVER_ERROR);
        };
    }

    private final ExceptionHandler exceptionHandler;

    public ConsentRequestAccessAuthorisationFilter(String consentRequestUserIdClaim, String ssoTokenUserIdKey, ExceptionHandler exceptionHandler) {
        Reject.ifBlank(consentRequestUserIdClaim, "consentRequestUserIdClaim must be supplied");
        Reject.ifBlank(ssoTokenUserIdKey, "ssoTokenUserIdKey must be supplied");
        Reject.ifNull(exceptionHandler, "exceptionHandler must be supplied");
        this.consentRequestUserIdClaim = consentRequestUserIdClaim;
        this.ssoTokenUserIdKey = ssoTokenUserIdKey;
        this.exceptionHandler = exceptionHandler;
    }

    @Override
    public Promise<Response, NeverThrowsException> filter(Context context, Request request, Handler next) {
        final String ssoTokenUserId;
        final String consentRequestUser;
        try {
            ssoTokenUserId = getUserIdFromSsoToken(context);
            consentRequestUser = getUserIdFromConsentRequestJwt(context);
        } catch (RuntimeException ex) {
            return Promises.newResultPromise(exceptionHandler.onException(context, ex));
        }

        LOGGER.info("Verifying ssoTokenUserId: {} matches consent request JWT username: {}", ssoTokenUserId, consentRequestUser);
        if (!ssoTokenUserId.equals(consentRequestUser)) {
            LOGGER.warn("User: {} not authorised to access consent", ssoTokenUserId);
            return Promises.newResultPromise(new Response(Status.UNAUTHORIZED));
        }
        LOGGER.debug("User authorised to access consent");
        return next.handle(context, request);
    }

    /**
     * Extracts the userId from the Consent Request's {@link JwtValidationContext}.
     * This uses the consentRequestUserIdClaim field to determine which claim contains the userId
     *
     * @param context Context, must contain a {@link JwtValidationContext}
     * @return the userId of the user that owns the consent
     */
    private String getUserIdFromConsentRequestJwt(Context context) {
        final JwtValidationContext consentRequestJwtValidationCtxt = context.asContext(JwtValidationContext.class);
        final Object usernameObj = consentRequestJwtValidationCtxt.getClaims().getClaim(consentRequestUserIdClaim);
        if (!(usernameObj instanceof String)) {
            throw new IllegalStateException("consent_request JWT username claim is missing or not a string");
        }
        return (String) usernameObj;
    }

    /**
     * Extracts the userId from the {@link SsoTokenContext}.
     * This uses the ssoTokenUserIdKey field to determine which info map key contains the userId.
     *
     * @param context Context, must contain a {@link SsoTokenContext}
     * @return the userId of the user with the active AM SSOToken
     */
    private String getUserIdFromSsoToken(Context context) {
        final SsoTokenContext ssoContext = context.asContext(SsoTokenContext.class);
        final Map<String, Object> info = ssoContext.getInfo();
        final Object userId = info.get(ssoTokenUserIdKey);
        if (!(userId instanceof String)) {
            throw new IllegalStateException("SsoTokenContext.uid is missing or not a string");
        }
        return (String) userId;
    }

    /**
     * Heaplet which creates {@link ConsentRequestAccessAuthorisationFilter}
     * <p>
     * Optional config:
     * - consentRequestUserIdClaim: the name of the claim in the consent_request JWT which contains the userId (default: username)
     * - ssoTokenUserIdKey: {@link SsoTokenContext#getInfo()} key which contains the userId (default: uid)
     * <p>
     * Example config:
     * {
     *             "name": "ConsentRequestAccessAuthorisationFilter",
     *             "type": "ConsentRequestAccessAuthorisationFilter",
     *             "comment": "Verify user SSO session is allowed to access the consent"
     * }
     */
    public static class Heaplet extends GenericHeaplet {
        @Override
        public Object create() throws HeapException {
            return new ConsentRequestAccessAuthorisationFilter(getConfig().get("consentRequestUserIdClaim")
                                                                   .defaultTo(DEFAULT_CONSENT_REQUEST_USER_ID_CLAIM)
                                                                   .asString(),
                                                               getConfig().get("ssoTokenUserIdKey")
                                                                   .defaultTo(DEFAULT_SSO_TOKEN_USER_ID_KEY)
                                                                   .asString(),
                                                               createDefaultExceptionHandler());
        }
    }
}
