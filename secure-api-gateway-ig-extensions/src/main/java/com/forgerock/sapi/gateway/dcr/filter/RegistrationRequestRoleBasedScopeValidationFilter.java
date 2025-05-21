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
package com.forgerock.sapi.gateway.dcr.filter;

import static org.forgerock.http.protocol.Response.newResponsePromise;
import static org.forgerock.openig.fapi.dcr.common.ErrorCode.INVALID_CLIENT_METADATA;
import static org.forgerock.openig.fapi.dcr.common.ErrorCode.INVALID_SOFTWARE_STATEMENT;
import static org.forgerock.openig.fapi.error.ErrorResponseUtils.errorResponse;
import static org.forgerock.util.promise.Promises.newExceptionPromise;
import static org.forgerock.util.promise.Promises.newVoidResultPromise;

import java.util.List;

import org.forgerock.http.Filter;
import org.forgerock.http.Handler;
import org.forgerock.http.protocol.Request;
import org.forgerock.http.protocol.Response;
import org.forgerock.openig.fapi.dcr.request.RegistrationRequest;
import org.forgerock.openig.fapi.dcr.request.RegistrationRequestException;
import org.forgerock.openig.fapi.dcr.request.RegistrationRequestFapiContext;
import org.forgerock.openig.heap.GenericHeaplet;
import org.forgerock.openig.heap.HeapException;
import org.forgerock.services.context.Context;
import org.forgerock.util.promise.NeverThrowsException;
import org.forgerock.util.promise.Promise;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * This {@link RegistrationRequestRoleBasedScopeValidationFilter} enforces registration scope validation by cross-reference
 * of permitted SSA roles.
 *
 * <p>Note that this scope validation is based around <i>Open Banking scope validation</i>, not strictly FAPI, for which
 * there are no specific scope validation roles. For backward compatibility support, we continue to support this form of
 * scope validation. Note that this will eventually be moved to the Open Banking-specific codebase.
 *
 * <p><i>As such, this class should not be used outside Ping-managed configuration.</i>
 *
 * <p>This {@link RegistrationRequestRoleBasedScopeValidationFilter} enforces the OBIE
 * <a href="https://openbankinguk.github.io/dcr-docs-pub/v3.3/dynamic-client-registration.html#data-mapping">
 *     dynamic client registration scope rule</a>, stating
 * <pre>
 * "scope: Specified in the scope claimed. This must be a subset of the scopes in the SSA"
 * </pre>
 *
 * <p>Note also that the
 * <a href=
 * "https://openbankinguk.github.io/dcr-docs-pub/v3.3/dynamic-client-registration.html#obclientregistrationrequest1">
 * data dictionary for OBClientRegistrationRequest1 </a>
 * states that:
 * <pre>
 *   scope     1..1     scope     Scopes the client is asking for (if not specified, default scopes are assigned by
 *   the AS). This consists of a list scopes separated by spaces.     String(256)
 * </pre>
 *
 * <p>In the Open Banking issued SSA we can find no scopes defined, however, we do have 'software_roles' which is an
 * array of strings containing AISP, PISP, or a subset thereof, or ASPSP. We must check that the scopes requested are
 * allowed according to the roles defined in the software statement.
 *
 */
public class RegistrationRequestRoleBasedScopeValidationFilter implements Filter {

    private static final Logger logger =
            LoggerFactory.getLogger(RegistrationRequestRoleBasedScopeValidationFilter.class);

    static final String ROLE_AISP = "AISP";
    static final String ROLE_CBPII = "CBPII";
    static final String ROLE_PISP = "PISP";
    static final String SCOPE_ACCOUNTS = "accounts";
    static final String SCOPE_FUNDS = "fundsconformations";
    static final String SCOPE_PAYMENTS = "payments";

    @Override
    public Promise<Response, NeverThrowsException> filter(final Context context,
                                                          final Request request,
                                                          final Handler next) {
        RegistrationRequest registrationRequest = context.asContext(RegistrationRequestFapiContext.class)
                                                         .getRegistrationRequest();
        return validate(registrationRequest)
                .thenAsync(ignored -> next.handle(context, request),
                           registrationException ->
                                   newResponsePromise(errorResponse(registrationException)));
    }

    private Promise<Void, RegistrationRequestException> validate(final RegistrationRequest registrationRequest) {
        String requestedScopes = registrationRequest.getScope();
        if (requestedScopes == null) {
            return newExceptionPromise(
                    new RegistrationRequestException(INVALID_CLIENT_METADATA,
                                                     "The request jwt does not contain the required scopes claim"));
        }
        List<String> ssaRoles = registrationRequest.getSoftwareStatement().getRoles();
        if (ssaRoles.isEmpty()) {
            return newExceptionPromise(new RegistrationRequestException(
                    INVALID_SOFTWARE_STATEMENT,
                    "The software_statement jwt does not contain a 'software_roles' claim"));
        }
        logger.debug("requestedScopes: {}, SSA roles: {}\"", requestedScopes, ssaRoles);

        if (requestedScopes.contains(SCOPE_ACCOUNTS) && !ssaRoles.contains(ROLE_AISP)) {
            String error = ("registration request contains scopes (%s) not allowed "
                    + "for the presented software statement (%s)").formatted(SCOPE_ACCOUNTS, ROLE_AISP);
            return newExceptionPromise(new RegistrationRequestException(INVALID_CLIENT_METADATA, error));
        }
        if (requestedScopes.contains(SCOPE_PAYMENTS) && !ssaRoles.contains(ROLE_PISP)) {
            String error = ("registration request contains scopes (%s) not allowed "
                    + "for the presented software statement (%s)").formatted(SCOPE_PAYMENTS, ROLE_PISP);
            return newExceptionPromise(new RegistrationRequestException(INVALID_CLIENT_METADATA, error));
        }
        if (requestedScopes.contains(SCOPE_FUNDS) && !ssaRoles.contains(ROLE_CBPII)) {
            String error = ("registration request contains scopes (%s) not allowed "
                    + "for the presented software statement (%s)").formatted(SCOPE_FUNDS, ROLE_CBPII);
            return newExceptionPromise(new RegistrationRequestException(INVALID_CLIENT_METADATA, error));
        }
        logger.debug("Open Banking scopes valid");
        return newVoidResultPromise();
    }

    /**
     * Create a {@link RegistrationRequestRoleBasedScopeValidationFilter} in a heap environment.
     */
    public static class Heaplet extends GenericHeaplet {
        @Override
        public Object create() throws HeapException {
            return new RegistrationRequestRoleBasedScopeValidationFilter();
        }
    }
}