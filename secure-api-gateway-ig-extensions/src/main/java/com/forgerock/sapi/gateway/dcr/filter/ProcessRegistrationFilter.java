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

import static java.util.Objects.requireNonNull;
import static org.forgerock.http.protocol.Response.newResponsePromise;
import static org.forgerock.http.protocol.Responses.newInternalServerError;
import static org.forgerock.json.JsonValue.json;
import static org.forgerock.openig.fapi.dcr.common.ErrorCode.INVALID_CLIENT_METADATA;
import static org.forgerock.openig.fapi.dcr.common.ErrorCode.UNKNOWN;
import static org.forgerock.openig.fapi.dcr.common.ErrorResponseUtils.errorResponse;
import static org.forgerock.openig.fapi.dcr.common.ErrorResponseUtils.errorResponseAsync;
import static org.forgerock.openig.util.JsonValues.requiredHeapObject;

import java.net.URISyntaxException;
import java.util.List;
import java.util.Set;

import org.forgerock.http.Filter;
import org.forgerock.http.Handler;
import org.forgerock.http.MutableUri;
import org.forgerock.http.protocol.Form;
import org.forgerock.http.protocol.Request;
import org.forgerock.http.protocol.Response;
import org.forgerock.json.JsonValue;
import org.forgerock.json.jose.jws.SignedJwt;
import org.forgerock.openig.fapi.apiclient.ApiClient;
import org.forgerock.openig.fapi.context.FapiContext;
import org.forgerock.openig.fapi.dcr.RegistrationRequest;
import org.forgerock.openig.fapi.dcr.SoftwareStatement;
import org.forgerock.openig.fapi.dcr.common.RegistrationException;
import org.forgerock.openig.fapi.jwks.JwkSetService;
import org.forgerock.openig.fapi.trusteddirectory.TrustedDirectoryService;
import org.forgerock.openig.heap.GenericHeaplet;
import org.forgerock.openig.heap.HeapException;
import org.forgerock.services.context.Context;
import org.forgerock.util.annotations.VisibleForTesting;
import org.forgerock.util.promise.NeverThrowsException;
import org.forgerock.util.promise.Promise;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


public final class ProcessRegistrationFilter implements Filter {

    private static final Logger logger = LoggerFactory.getLogger(ProcessRegistrationFilter.class);

    private static final String FAPI_INIT_ERROR = "Fapi initialization error - "
            + "FapiInitializerFilter may not have been configured";
    // Metadata
    public static final String METADATA_TLS_CLIENT_CERTIFICATE_BOUND_ACCESS_TOKENS =
            "tls_client_certificate_bound_access_tokens";
    public static final String CLAIM_SOFTWARE_STATEMENT = "software_statement";
    public static final String PARAM_CLIENT_ID = "client_id";

    @Override
    public Promise<Response, NeverThrowsException> filter(final Context context,
                                                          final Request request,
                                                          final Handler next) {
        if (logger.isDebugEnabled()) {
            // TODO: Add to FapiContext?
            String fapiInteractionId = request.getHeaders().getFirst("x-fapi-interaction-id");
            FapiContext fapiContext = fapiContext(context);
            RegistrationRequest registrationRequest = fapiContext.getRegistrationRequest();
            SoftwareStatement softwareStatement = registrationRequest.getSoftwareStatement();
            String apiClientOrgId = softwareStatement.getOrganisationId();
            String apiClientOrgName = softwareStatement.getOrganisationName() != null
                    ? softwareStatement.getOrganisationName()
                    : apiClientOrgId;
            logger.debug("Registration ({}) apiClient: org id: '{}', org name: '{}, SSA: {}",
                         fapiInteractionId,
                         apiClientOrgId,
                         apiClientOrgName,
                         softwareStatement.getSoftwareStatementAssertion().build());
        }
        String requestMethod = request.getMethod();
        return switch (requestMethod) {
            case "POST" -> handlePost(context, request, next);
            case "PUT" -> handlePut(context, request, next);
            case "GET" -> handleGet(context, request, next);
            case "DELETE" -> handleDelete(context, request, next);
            default -> newResponsePromise(errorResponse(
                    new RegistrationException(UNKNOWN,
                                              "Request method '%s' not supported".formatted(requestMethod))));
        };
    }

    private Promise<Response, NeverThrowsException> handlePost(final Context context,
                                                               final Request request,
                                                               final Handler next) {
        FapiContext fapiContext = fapiContext(context);
        RegistrationRequest registrationRequest = fapiContext.getRegistrationRequest();
        if (registrationRequest == null) {
            // TODO[OPENIG-9136] Null handling should become redundant here
            return errorResponseAsync(new RegistrationException(INVALID_CLIENT_METADATA,
                                                                "request object is invalid or missing"));
        }
        registrationRequest.setMetadata(METADATA_TLS_CLIENT_CERTIFICATE_BOUND_ACCESS_TOKENS, true);
        attachRawRegistrationRequest(request, registrationRequest);
        return next.handle(context, request);
    }

    private Promise<Response, NeverThrowsException> handlePut(final Context context,
                                                              final Request request,
                                                              final Handler next) {
        FapiContext fapiContext = fapiContext(context);
        RegistrationRequest registrationRequest = fapiContext.getRegistrationRequest();
        if (registrationRequest == null) {
            // TODO[OPENIG-9136] Null handling should become redundant here
            return errorResponseAsync(new RegistrationException(INVALID_CLIENT_METADATA,
                                                                "request object is invalid or missing"));
        }
        registrationRequest.setMetadata(METADATA_TLS_CLIENT_CERTIFICATE_BOUND_ACCESS_TOKENS, true);
        rewriteUriToAccessExistingAmRegistration(request);
        return next.handle(context, request);
    }

    private Promise<Response, NeverThrowsException> handleGet(final Context context,
                                                              final Request request,
                                                              final Handler next) {
        FapiContext fapiContext = fapiContext(context);
        rewriteUriToAccessExistingAmRegistration(request);
        return next.handle(context, request);
    }

    private Promise<Response, NeverThrowsException> handleDelete(final Context context,
                                                                 final Request request,
                                                                 final Handler next) {
        rewriteUriToAccessExistingAmRegistration(request);
        return next.handle(context, request);
    }

    /*
     * Convenience to map the context to its FapiContext, handling misconfiguration errors.
     */
    private static FapiContext fapiContext(final Context context) {
        return context.as(FapiContext.class)
                      .orElseThrow(() -> {
                          String errorMessage = ("Fapi initialization error - FapiInitializerFilter may not have "
                                  + "been configured: FapiContext not found");
                          return new IllegalStateException(errorMessage);
                      });
    }

    /*
     * AM doesn't understand JWS encoded registration requests, so we need to convert the jwt JSON and pass it
     * on.
     */
    private void attachRawRegistrationRequest(final Request request, final RegistrationRequest registrationRequest) {
        request.getEntity().setJson(registrationRequest.toJsonValue());
    }

    /**
     * Transforms the Request URI from OpenBanking URI form (REST) to AM form, for operations on an existing
     * registration where an existing API client ID is provided.
     *
     * <p>This rewrites from the OpenBanking form, as follows:
     * <pre>    am/oauth2/realms/root/realms/alpha/register/8ed73b58-bd18-41c4-93f3-7a1bbf57a7eb</pre>
     * <p>to the AM form, as follows:
     * <pre>    am/oauth2/realms/root/realms/alpha/register?client_id=8ed73b58-bd18-41c4-93f3-7a1bbf57a7eb</pre>
     * @param request the registration request
     */
    @VisibleForTesting
    static void rewriteUriToAccessExistingAmRegistration(final Request request) {
        MutableUri requestUri = request.getUri();
        String path = requestUri.getPath();
        int lastSlashIndex = path.lastIndexOf("/");
        if (lastSlashIndex == -1) {
            throw new IllegalStateException("API Client ID path parameter not found");
        }
        String apiClientId = path.substring(lastSlashIndex + 1);
        try {
            Form clientIdParam = new Form();
            clientIdParam.add(PARAM_CLIENT_ID, apiClientId);
            requestUri.setRawPath(path.substring(0, lastSlashIndex));
            requestUri.setRawQuery(clientIdParam.toQueryString());
        } catch (URISyntaxException e) {
            throw new IllegalStateException("API Client ID path parameter not found");
        }
    }

    public static class Heaplet extends GenericHeaplet {
        // TODO: Remove or refactor into IG chain.

        /** Public name used by resolver. */
        public static final String NAME = "ProcessRegistrationFilter";

        @Override
        public Object create() throws HeapException {
            return new ProcessRegistrationFilter();
        }
    }
}
