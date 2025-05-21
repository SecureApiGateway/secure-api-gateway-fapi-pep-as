package com.forgerock.sapi.gateway.dcr.filter;

import static java.util.Objects.requireNonNull;
import static org.forgerock.http.protocol.Response.newResponsePromise;
import static org.forgerock.json.JsonValue.field;
import static org.forgerock.json.JsonValue.fieldIfNotNull;
import static org.forgerock.json.JsonValue.json;
import static org.forgerock.json.JsonValue.object;
import static org.forgerock.openig.fapi.dcr.common.ErrorCode.INVALID_CLIENT_METADATA;
import static org.forgerock.openig.fapi.dcr.common.ErrorCode.INVALID_SOFTWARE_STATEMENT;
import static org.forgerock.util.promise.Promises.newExceptionPromise;
import static org.forgerock.util.promise.Promises.newResultPromise;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.forgerock.http.Filter;
import org.forgerock.http.Handler;
import org.forgerock.http.protocol.Request;
import org.forgerock.http.protocol.Response;
import org.forgerock.http.protocol.Status;
import org.forgerock.json.JsonValue;
import org.forgerock.openig.fapi.dcr.common.ErrorCode;
import org.forgerock.openig.fapi.dcr.request.RegistrationRequest;
import org.forgerock.openig.fapi.dcr.request.RegistrationRequestException;
import org.forgerock.openig.fapi.dcr.request.RegistrationRequestFapiContext;
import org.forgerock.services.context.Context;
import org.forgerock.util.promise.NeverThrowsException;
import org.forgerock.util.promise.Promise;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * This {@link RegistrationRequestScopeValidationFilter} enforces the OBIE
 * <a href="https://openbankinguk.github.io/dcr-docs-pub/v3.3/dynamic-client-registration.html#data-mapping">
 * dynamic client registration scope rule</a>, which states:<p>
 * <pre>
 *   "scope: Specified in the scope claimed. This must be a subset of the scopes in the SSA"
 * </pre>
 * <p>
 * Note also that the
 * <a href=
 * "https://openbankinguk.github.io/dcr-docs-pub/v3.3/dynamic-client-registration.html#obclientregistrationrequest1">
 * data dictionary for OBClientRegistrationRequest1 </a> rule states that:
 * <pre>
 *   "scope     1..1     scope     Scopes the client is asking for (if not specified, default scopes are assigned by
 *                                 the AS). This consists of a list scopes separated by spaces. String(256)"
 * </pre>
 *
 * In the Open Banking issued SSA we can find no scopes defined, however, we do have 'software_roles' which is an array
 * of strings containing AISP, PISP, or a subset thereof, or ASPSP. We must check that the scopes requested are allowed
 * according to the roles defined in the software statement.
 */
public class RegistrationRequestScopeValidationFilter implements Filter {

    private static final Logger logger = LoggerFactory.getLogger(RegistrationRequestScopeValidationFilter.class);

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
                .thenAsync(ignore -> next.handle(context, request),
                           dcrException ->
                                   newResponsePromise(errorResponse(Status.BAD_REQUEST,
                                                                    dcrException.getErrorCode(),
                                                                    dcrException.getErrorDescription())));
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
            return newExceptionPromise(
                    new RegistrationRequestException(INVALID_SOFTWARE_STATEMENT,
                                                     "The software_statement jwt does not contain a "
                                                             + "'software_roles' claim"));
        }
        logger.debug("requestedScopes: {}, SSA roles: {}\"", requestedScopes, ssaRoles);

        if (requestedScopes.contains(SCOPE_ACCOUNTS) && !ssaRoles.contains(ROLE_AISP)) {
            String error = ("registration request contains scopes (%s) not allowed "
                    + "for the presented software statement (%s)").formatted(
                    SCOPE_ACCOUNTS,
                    ROLE_AISP);
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
        return newResultPromise(null);
    }

    public static Response errorResponse(final Status status, final ErrorCode error, final String errorDescription) {
        Response response = new Response(status);
        JsonValue errorJson = json(object(
                field("error", requireNonNull(error, "error attribute is mandatory").getCode()),
                fieldIfNotNull("error_description", errorDescription)));
        response.getEntity().setJson(errorJson);
        logger.warn("DCR Request failed validation, errorResponse: {}", errorJson);
        return response;
    }
}
