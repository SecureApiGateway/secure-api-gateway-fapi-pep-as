import static org.forgerock.http.protocol.Response.newResponsePromise
import static org.forgerock.util.promise.Promises.newExceptionPromise
import static org.forgerock.util.promise.Promises.newResultPromise

import org.forgerock.json.jose.exceptions.FailedToLoadJWKException
import org.forgerock.json.jose.jwk.JWK
import org.forgerock.openig.fapi.dcr.RegistrationRequest
import org.forgerock.openig.fapi.dcr.SoftwareStatement

import com.forgerock.securebanking.uk.gateway.jwks.*
import com.nimbusds.jose.jwk.RSAKey
import com.securebanking.gateway.dcr.ErrorResponseFactory

/*
 * Script to verify the registration request, and prepare AM OIDC dynamic client reg
 * Input:  Registration JWT
 * Output: Verified OIDC registration JSON
 *
 * Relevant specifications:
 * https://openbankinguk.github.io/dcr-docs-pub/v3.3/dynamic-client-registration.html#data-mapping
 * https://openid.net/specs/openid-connect-registration-1_0.html
 * https://datatracker.ietf.org/doc/html/rfc7591
 *
 * NOTE: This filter should be used AFTER the FapiAdvancedDCRValidationFilter. That filter will check that the request
 * is fapi compliant:
 * - validateRedirectUris
 *   - request object must contain redirect_uris field
 *   - redirect_uris array must not be empty
 *   - redirect_uris contain valid URIs
 *   - redirect_uris must use https scheme
 * - validateResponseTypes
 *   - request object must contain field: response_types
 *   - response types are FAPI compliant, i.e. "code" or "code id_token"
 *   - if response type is "code", response_mode is "jwt"
 *   - if response type is "code id_token" then request must contain field 'scope' and scope must contain 'openid'
 * - validateSigningAlgorithmUsed
 *   - that the signing algorithm supported is PS256
 * - validateTokenEndpointAuthMethods
 *   - request object must contain field: token_endpoint_auth_method
 *   - that token_endpoint_auth_method is a valid value, either 'private_key_jwt' or 'tls_client_auth'
 */

def fapiInteractionId = request.getHeaders().getFirst("x-fapi-interaction-id");
if (fapiInteractionId == null) fapiInteractionId = "No x-fapi-interaction-id"
SCRIPT_NAME = "[ProcessRegistration] (" + fapiInteractionId + ") - "
logger.debug(SCRIPT_NAME + "Running...")

def errorResponseFactory = new ErrorResponseFactory(SCRIPT_NAME)

def defaultResponseTypes = "code id_token"
def supportedResponseTypes = [defaultResponseTypes, "code"]

def method = request.method

switch (method.toUpperCase()) {
    case "POST":
    case "PUT":
        if (!attributes.registrationRequest) {
            logger.error(SCRIPT_NAME + "RegistrationRequestEntityValidatorFilter must be run prior to this script")
            return new Response(Status.INTERNAL_SERVER_ERROR)
        }
        logger.debug(SCRIPT_NAME + "required registrationRequest is present")

        RegistrationRequest registrationRequest = attributes.registrationRequest

        // Check we have everything we need from the client certificate
        if (!attributes.clientCertificate) {
            return errorResponseFactory.invalidClientMetadataErrorResponse("No client certificate for registration")
        }

        List<String> responseTypes = registrationRequest.getResponseTypes()
        if(responseTypes == null || responseTypes.isEmpty()){
            logger.debug(SCRIPT_NAME + "No response_types claim in registration request. Setting default response_types " +
                    "to " + defaultResponseTypes)
            registrationRequest.setResponseTypes([defaultResponseTypes])
        } else {
            // https://datatracker.ietf.org/doc/html/rfc7591#section-3.2.1 states that:
            //   "The authorization server MAY reject or
            //   replace any of the client's requested metadata values submitted
            //   during the registration and substitute them with suitable values."
            for (String responseType : responseTypes) {
                if (!supportedResponseTypes.contains(responseType)){
                    logger.debug(SCRIPT_NAME + "response_types claim does not include supported types. " +
                            "Setting default response_types to " + defaultResponseTypes)
                    registrationRequest.setResponseTypes([defaultResponseTypes])
                    break
                }
            }
        }
        logger.debug("{}response_types claim value is {}", SCRIPT_NAME, registrationRequest.getResponseTypes())

        // Check token_endpoint_auth_methods. OB Spec says this MUST be defined with 1..1 cardinality in the
        // registration request.
        String tokenEndpointAuthMethod = registrationRequest.getTokenEndpointAuthMethod()

        if (tokenEndpointAuthMethod == null || !tokenEndpointAuthMethodsSupported.contains(tokenEndpointAuthMethod)){
            String errorDescription = "token_endpoint_auth_method claim must be one of: " +
                    tokenEndpointAuthMethodsSupported
            logger.info("{}{}", SCRIPT_NAME, errorDescription)
            return errorResponseFactory.invalidClientMetadataErrorResponse(errorDescription)
        }
        logger.debug("{}token_endpoint_auth_method is {}", SCRIPT_NAME, tokenEndpointAuthMethod)

        // AM should reject this case?
        if (tokenEndpointAuthMethod.equals("tls_client_auth") && registrationRequest.getMetadata("tls_client_auth_subject_dn").isNull()) {
            return errorResponseFactory.invalidClientMetadataErrorResponse("tls_client_auth_subject_dn must be provided to use tls_client_auth")
        }

        SoftwareStatement softwareStatement = registrationRequest.getSoftwareStatement()
        logger.debug(SCRIPT_NAME + "Got ssa [" + softwareStatement.getSoftwareStatementAssertion().build() + "]")

        def apiClientOrgId = softwareStatement.getOrganisationId()
        def apiClientOrgName = softwareStatement.getOrganisationName() !=null ? softwareStatement.getOrganisationName() : apiClientOrgId
        logger.debug(SCRIPT_NAME + "Inbound details from SSA: apiClientOrgName: {} apiClientOrgCertId: {}",
                apiClientOrgName,
                apiClientOrgId
        )

        // ToDo: Why is this here?
        String subjectType = registrationRequest.getMetadata("subject_type").asString()
        if (subjectType == null) {
            logger.debug("subjectType is not set. Setting to 'pairwise'", SCRIPT_NAME)
            registrationRequest.setMetadata("subject_type", "pairwise");
        }
        logger.debug("{} subject_type is '{}'", SCRIPT_NAME, subjectType)

        Response errorResponse = performOpenBankingScopeChecks(errorResponseFactory, registrationRequest)
        if (errorResponse != null) {
            return errorResponse
        }

        try {
            validateRegistrationRedirectUris(registrationRequest)
        } catch (IllegalStateException e){
            return errorResponseFactory.invalidRedirectUriErrorResponse(e.getMessage())
        }

        registrationRequest.setMetadata("tls_client_certificate_bound_access_tokens", true)

        // Put is editing an existing registration, so needs the client_id param in the uri
        if (request.method == "PUT") {
            rewriteUriToAccessExistingAmRegistration()
        }

        return softwareStatement.getJwkSetLocator().applyAsync(uri -> {
            registrationRequest.setMetadata("jwks_uri", uri.toString());
            return jwkSetService.getJwkSet(uri)
        }, apiClientJwkSet -> {
            if (!allowIgIssuedTestCerts) {
                return newExceptionPromise(new FailedToLoadJWKException("software_statement must contain software_jwks_endpoint"))
            }

            // We need to set the jwks claim in the registration request because the software statement might not
            // have the jwks in the jwks claim in the software statement. If that were the case it would result in
            // AM being unable to validate client credential jws used in `private_key_jwt` as the
            // `token_endpoint_auth_method`.
            registrationRequest.setMetadata("jwks", apiClientJwkSet.toJsonValue())
            return newResultPromise(apiClientJwkSet)

        }).thenAsync(apiClientJwkSet -> {
            logger.debug(SCRIPT_NAME + "Checking cert against ssa software_jwks: " + apiClientJwkSet)
            if (!tlsClientCertExistsInJwkSet(apiClientJwkSet)) {
                String errorDescription = "tls transport cert does not match any certs registered in jwks for software " +
                        "statement"
                logger.debug("{}{}", SCRIPT_NAME, errorDescription)
                return newResultPromise(errorResponseFactory.invalidSoftwareStatementErrorResponse(errorDescription))
            }
            // AM doesn't understand JWS encoded registration requests, so we need to convert the jwt JSON and pass it on
            // However, this might not be the best place to do that?
            def regJson = registrationRequest.toJsonValue()
            logger.debug(SCRIPT_NAME + "final json [" + regJson + "]")
            request.setEntity(regJson)

            return next.handle(context, request)
                       .thenAsync(response -> addSoftwareStatementToResponse(response, softwareStatement.getSoftwareStatementAssertion()))

        }, e -> newResponsePromise(errorResponseFactory.invalidClientMetadataErrorResponse(e.message)))

    case "DELETE":
        rewriteUriToAccessExistingAmRegistration()
        return next.handle(context, request)
    case "GET":
        rewriteUriToAccessExistingAmRegistration()
        return next.handle(context, request)
                .thenAsync(response -> {
                    var apiClient = attributes.apiClient
                    if (apiClient && apiClient.softwareStatementAssertion) {
                        return addSoftwareStatementToResponse(response, apiClient.softwareStatementAssertion)
                    }
                    return newResultPromise(response)
                })
    default:
        logger.debug(SCRIPT_NAME + "Method not supported")
        return next.handle(context, request)

}


/**
 * Validate the redirect_uris claim in the registration request is valid as per the OB DCR spec:
 * https://openbankinguk.github.io/dcr-docs-pub/v3.2/dynamic-client-registration.html
 */
private void validateRegistrationRedirectUris(RegistrationRequest registrationRequest) {
    List<URI> regRedirectUris = registrationRequest.getRedirectUris()
    SoftwareStatement softwareStatement = registrationRequest.getSoftwareStatement()
    List<URI> ssaRedirectUris = softwareStatement.getRedirectUris()

    for(URI regRequestRedirectUri : regRedirectUris){
        if(!"https".equals(regRequestRedirectUri.getScheme())){
            throw new IllegalStateException("invalid registration request redirect_uris value: " + regRequestRedirectUri + " must use https")
        }

        if("localhost".equals(regRequestRedirectUri.getHost())){
            throw new IllegalStateException("invalid registration request redirect_uris value: " + regRequestRedirectUri + " must not point to localhost")
        }

        if(!ssaRedirectUris.contains(regRequestRedirectUri)){
            throw new IllegalStateException("invalid registration request redirect_uris value, must match or be a subset of the software_redirect_uris")
        }
        return
    }
}

/**
 * This method enforces the rule set by OBIE
 * <a href="https://openbankinguk.github.io/dcr-docs-pub/v3.3/dynamic-client-registration.html#data-mapping">here</a>
 * that states:
 * "scope: Specified in the scope claimed. This must be a subset of the scopes in the SSA"
 * also in the
 * <a href="https://openbankinguk.github.io/dcr-docs-pub/v3.3/dynamic-client-registration.html#obclientregistrationrequest1">
 * data dictionary for OBClientRegistrationRequest1 </a>
 * it is stated that:
 * "scope     1..1     scope     Scopes the client is asking for (if not specified, default scopes are assigned by the AS).
 * This consists of a list scopes separated by spaces.     String(256)"
 *
 * In the Open Banking issued SSA we can find no scopes defined, however, we do have 'software_roles' which is an array
 * of strings containing AISP, PISP, or a subset thereof, or ASPSP. We must check that the scopes requested are allowed
 * according to the roles defined in the software statement.
 *
 * @param registrationRequestClaims The claims from the registration request jwt
 * @param ssaClaims the claims from the ssa
 * @return false if the OBIE specification rules are met, true if they are not
 */
private Response performOpenBankingScopeChecks(ErrorResponseFactory errorResponseFactory,
                                               RegistrationRequest registrationRequest) {
    logger.debug("{}performing OpenBanking Scope tests", SCRIPT_NAME)

    String requestedScopes = registrationRequest.getScope()
    if (requestedScopes == null) {
        String errorDescription = "The request jwt does not contain the required scopes claim"
        logger.info(SCRIPT_NAME + errorDescription)
        return errorResponseFactory.invalidClientMetadataErrorResponse(errorDescription)
    }
    logger.debug("{}requestedScopes are {}", SCRIPT_NAME, requestedScopes)

    List<String> ssaRoles = registrationRequest.getSoftwareStatement().getRoles()
    if (ssaRoles == null || ssaRoles.isEmpty()) {
        String errorDescription = "The software_statement jwt does not contain a 'software_roles' claim"
        logger.debug(SCRIPT_NAME + errorDescription)
        return errorResponseFactory.invalidSoftwareStatementErrorResponse(errorDescription)
    }
    logger.debug("{}ssaRoles are {}", SCRIPT_NAME, ssaRoles)

    if (requestedScopes.contains("accounts") && !ssaRoles.contains("AISP")) {
        String errorDescription = "registration request contains scopes not allowed " +
                "for the presented software statement"
        logger.debug("{}{}{}", SCRIPT_NAME, errorDescription, ": accounts")
        return errorResponseFactory.invalidClientMetadataErrorResponse(errorDescription)
    }

    if (requestedScopes.contains("payments") && !ssaRoles.contains("PISP")) {
        String errorDescription = "registration request contains scopes not allowed " +
                "for the presented software statement"
        logger.debug("{}{}{}", SCRIPT_NAME, errorDescription, ": payments")
        return errorResponseFactory.invalidClientMetadataErrorResponse(errorDescription)
    }

    if (requestedScopes.contains("fundsconformations") && !ssaRoles.contains("CBPII")) {
        String errorDescription = "registration request contains scopes not allowed " +
                "for the presented software statement"
        logger.debug("{}{}{}", SCRIPT_NAME, errorDescription, ": fundsconformations")
        return errorResponseFactory.invalidClientMetadataErrorResponse(errorDescription)
    }

    logger.debug("{} passed Open Banking scope tests", SCRIPT_NAME)
    return null;
}

/**
 * For operations on an existing registration, AM expects a uri of the form:
 *   am/oauth2/realms/root/realms/alpha/register?client_id=8ed73b58-bd18-41c4-93f3-7a1bbf57a7eb
 *
 * This method takes the OB uri form: am/oauth2/realms/root/realms/alpha/8ed73b58-bd18-41c4-93f3-7a1bbf57a7eb and
 * rewrites it to the AM form.
 */
private void rewriteUriToAccessExistingAmRegistration() {
    def path = request.uri.path
    def lastSlashIndex = path.lastIndexOf("/")
    def apiClientId = path.substring(lastSlashIndex + 1)
    request.uri.setRawPath(path.substring(0, lastSlashIndex))
    request.uri.setRawQuery("client_id=" + apiClientId)
}

private Promise addSoftwareStatementToResponse(response, softwareStatementAssertion) {
    if (response.status.isSuccessful()) {
        return response.getEntity().getJsonAsync().then(json -> {
            if (!json.isDefined("software_statement")) {
                json.put("software_statement", softwareStatementAssertion.build())
            }
            response.entity.setJson(json)
            return response
        })
    }
    return newResultPromise(response)
}

private boolean tlsClientCertExistsInJwkSet(jwkSet) {
    def tlsClientCert = attributes.clientCertificate
    // RSAKey.parse produces a JWK, we can then extract the cert from the x5c field
    def tlsClientCertX5c = RSAKey.parse(tlsClientCert).getX509CertChain().get(0).toString()
    for (JWK jwk : jwkSet.getJWKsAsList()) {
        final List<String> x509Chain = jwk.getX509Chain();
        final String jwkX5c = x509Chain.get(0);
        if ("tls".equals(jwk.getUse()) && tlsClientCertX5c.equals(jwkX5c)) {
            logger.debug(SCRIPT_NAME + "Found matching tls cert for provided pem, with kid: " + jwk.getKeyId()
                    + " x5t#S256: " + jwk.getX509ThumbprintS256())
            return true
        }
    }
    logger.debug(SCRIPT_NAME + "tls transport cert does not match any certs registered in jwks for software statement")
    return false
}


