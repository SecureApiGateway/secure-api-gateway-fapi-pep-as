import org.forgerock.json.jose.jwk.JWKSet
import org.forgerock.json.jose.jwk.JWK
import com.forgerock.sapi.gateway.common.jwt.ClaimsSetFacade
import com.forgerock.sapi.gateway.common.jwt.JwtException
import com.forgerock.sapi.gateway.dcr.models.RegistrationRequest
import com.forgerock.sapi.gateway.dcr.models.SoftwareStatement
import com.forgerock.securebanking.uk.gateway.jwks.*
import com.nimbusds.jose.jwk.RSAKey
import com.securebanking.gateway.dcr.ErrorResponseFactory

import java.security.SignatureException

import static org.forgerock.util.promise.Promises.newResultPromise

/**
 * TODO Remove remaining OpenBankingUK functionality from this script
 *
 * The script only allows DCRs to be made using the SAPI-G Test Trusted Directory.
 */
SCRIPT_NAME = "[ProcessRegistration] - "
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
        if (! registrationRequest.signatureHasBeenValidated() ){
            logger.error(SCRIPT_NAME + "registrationResponse signature has not been validated. " +
                    "RegistrationRequestJwtSignatureValidatorFilter must be run prior to this script")
            return new Response(Status.INTERNAL_SERVER_ERROR)
        }
        logger.debug(SCRIPT_NAME + "required registrationRequest signatures have been validated")

        // Check we have everything we need from the client certificate
        if (!attributes.clientCertificate) {
            return errorResponseFactory.invalidClientMetadataErrorResponse("No client certificate for registration")
        }

        if (registrationRequest.hasExpired()){
            logger.debug(SCRIPT_NAME + "Registration request JWT has expired")
            return errorResponseFactory.invalidClientMetadataErrorResponse("registration request jwt has expired")
        }
        logger.debug(SCRIPT_NAME + "registrationRequest is still valid");

        ClaimsSetFacade regRequestClaimsSet = registrationRequest.getClaimsSet()
        Optional<List<String>> optionalResponseTypes = regRequestClaimsSet.getOptionalStringListClaim("response_types")
        if(optionalResponseTypes.isEmpty()){
            logger.debug(SCRIPT_NAME + "No response_types claim in registration request. Setting default response_types " +
                    "to " + defaultResponseTypes)
            registrationRequest.setResponseTypes([defaultResponseTypes])
        } else {
            // https://datatracker.ietf.org/doc/html/rfc7591#section-3.2.1 states that:
            //   "The authorization server MAY reject or
            //   replace any of the client's requested metadata values submitted
            //   during the registration and substitute them with suitable values."

            def responseTypes = optionalResponseTypes.get()
            for (String responseType : responseTypes) {
                if (!supportedResponseTypes.contains(responseType)){
                    logger.debug(SCRIPT_NAME + "response_types claim does not include supported types. " +
                            "Setting default response_types to " + defaultResponseTypes)
                    registrationRequest.setResponseTypes([defaultResponseTypes])
                    break
                }
            }
        }
        logger.debug("{}response_types claim value is {}", SCRIPT_NAME, optionalResponseTypes.get())

        // Check token_endpoint_auth_methods. OB Spec says this MUST be defined with 1..1 cardinality in the
        // registration request.
        String tokenEndpointAuthMethod
        try {
            tokenEndpointAuthMethod = regRequestClaimsSet.getStringClaim("token_endpoint_auth_method")
        } catch (JwtException jwtException){
            String errorDescription = "registration request jwt must have a 'token_endpoint_auth_method' claim"
            logger.info("{}{}", SCRIPT_NAME, errorDescription)
            return errorResponseFactory.invalidClientMetadataErrorResponse(errorDescription)
        }

        if (!tokenEndpointAuthMethodsSupported.contains(tokenEndpointAuthMethod)){
            String errorDescription = "token_endpoint_auth_method claim must be one of: " +
                    tokenEndpointAuthMethodsSupported
            logger.info("{}{}", SCRIPT_NAME, errorDescription)
            return errorResponseFactory.invalidClientMetadataErrorResponse(errorDescription)
        }
        logger.debug("{}token_endpoint_auth_method is {}", SCRIPT_NAME, tokenEndpointAuthMethod)


        // AM should reject this case??
        if (tokenEndpointAuthMethod.equals("tls_client_auth") && !regRequestClaimsSet.getStringClaim("tls_client_auth_subject_dn")) {
            return errorResponseFactory.invalidClientMetadataErrorResponse("tls_client_auth_subject_dn must be provided to use tls_client_auth")
        }

        SoftwareStatement softwareStatement = registrationRequest.getSoftwareStatement()
        logger.debug(SCRIPT_NAME + "Got ssa [" + softwareStatement + "]")

        // This is OB specific
        // Validate the issuer claim for the registration matches the SSA software_id
        // NOTE: At this stage we do not know if the SSA is valid, it is assumed the SSAVerifier filter will run after
        //       this filter and raise an error if the SSA is invalid.
        String registrationIssuer = registrationRequest.getIssuer()
        String ssaSoftwareId = softwareStatement.getSoftwareId()
        logger.debug("{}registrationIssuer is {}, ssaSoftwareId is {}", SCRIPT_NAME, registrationIssuer, ssaSoftwareId)
        if (registrationIssuer == null || ssaSoftwareId == null || registrationIssuer != ssaSoftwareId) {
            return errorResponseFactory.invalidClientMetadataErrorResponse("invalid issuer claim")
        }

        def apiClientOrgId = softwareStatement.getOrgId()
        def apiClientOrgName = softwareStatement.getOrgName() !=null ? softwareStatement.getOrgName() : apiClientOrgId
        logger.debug(SCRIPT_NAME + "Inbound details from SSA: apiClientOrgName: {} apiClientOrgCertId: {}",
                apiClientOrgName,
                apiClientOrgId
        )

        // ToDo: Why is this here?
        String subject_type
        try{
            subject_type = regRequestClaimsSet.getStringClaim("subject_type");
        } catch (JwtException jwtException) {
            logger.debug("subject_type is not set. Setting to 'pairwise'", SCRIPT_NAME)
            regRequestClaimsSet.setStringClaim("subject_type", "pairwise");
        }
        logger.debug("{} subject_type is '{}'", SCRIPT_NAME, subject_type)

        try {
            validateRegistrationRedirectUris(registrationRequest)
        } catch (IllegalStateException e){
            return errorResponseFactory.invalidRedirectUriErrorResponse(e.getMessage())
        }

        regRequestClaimsSet.setClaim("tls_client_certificate_bound_access_tokens", true)

        // Put is editing an existing registration, so needs the client_id param in the uri
        if (request.method == "PUT") {
            rewriteUriToAccessExistingAmRegistration()
        }

        // Verify against the software_jwks which is a JWKSet embedded within the software_statement
        // NOTE: this is only suitable for developer testing purposes

        if (!allowIgIssuedTestCerts) {
            String errorDescription = "software_statement must contain software_jwks_endpoint"
            return errorResponseFactory.invalidSoftwareStatementErrorResponse(errorDescription)
        }
        JWKSet apiClientJwkSet = softwareStatement.getJwksSet()

        // We need to set the jwks claim in the registration request because the software statement might not
        // have the jwks in the jwks claim in the software statement. If that were the case it would result in
        // AM being unable to validate client credential jws used in `private_key_jwt` as the
        // `token_endpoint_auth_method`.
        regRequestClaimsSet.setClaim("jwks", apiClientJwkSet.toJsonValue());

        // AM doesn't understand JWS encoded registration requests, so we need to convert the jwt JSON and pass it on
        // However, this might not be the best place to do that?
        def regJson = regRequestClaimsSet.build();
        logger.debug(SCRIPT_NAME + "final json [" + regJson + "]")
        request.setEntity(regJson)

        logger.debug(SCRIPT_NAME + "Checking cert against ssa software_jwks: " + apiClientJwkSet)
        if (!tlsClientCertExistsInJwkSet(apiClientJwkSet)) {
            String errorDescription = "tls transport cert does not match any certs registered in jwks for software " +
                    "statement"
            logger.debug("{}{}", SCRIPT_NAME, errorDescription)
            return newResultPromise(errorResponseFactory.invalidSoftwareStatementErrorResponse(errorDescription))
        }
        return next.handle(context, request)
                .thenOnResult(response -> addSoftwareStatementToResponse(response, softwareStatement.getB64EncodedJwtString()))

    case "DELETE":
        rewriteUriToAccessExistingAmRegistration()
        return next.handle(context, request)
    case "GET":
        rewriteUriToAccessExistingAmRegistration()
        return next.handle(context, request)
                .thenOnResult(response -> {
                    var apiClient = attributes.apiClient
                    if (apiClient && apiClient.softwareStatementAssertion) {
                        addSoftwareStatementToResponse(response, apiClient.softwareStatementAssertion)
                    }
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
    List<URL> regRedirectUris = registrationRequest.getRedirectUris()
    SoftwareStatement softwareStatement = registrationRequest.getSoftwareStatement()
    List<URL> ssaRedirectUris = softwareStatement.getRedirectUris()

    for(URL regRequestRedirectUri : regRedirectUris){
        if(!"https".equals(regRequestRedirectUri.getProtocol())){

            throw new IllegalStateException("invalid registration request redirect_uris value: " + regRedirect + " must use https")
        }

        if("localhost".equals(regRequestRedirectUri.getHost())){
            throw new IllegalStateException("invalid registration request redirect_uris value: " + regRedirect + " must not point to localhost")
        }

        if(!ssaRedirectUris.contains(regRequestRedirectUri)){
            throw new IllegalStateException("invalid registration request redirect_uris value, must match or be a subset of the software_redirect_uris")
        }
    }
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

private void addSoftwareStatementToResponse(response, softwareStatementAssertion) {
    if (response.status.isSuccessful()) {
        var registrationResponse = response.getEntity().getJson()
        if (!registrationResponse["software_statement"]) {
            registrationResponse["software_statement"] = softwareStatementAssertion.build()
        }
        response.entity.setJson(registrationResponse)
    }
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

private boolean validateRegistrationJwtSignature(jwt, jwkSet) {
    try {
        jwtSignatureValidator.validateSignature(jwt, jwkSet)
        return true
    } catch (SignatureException se) {
        logger.warn(SCRIPT_NAME + "jwt signature validation failed", se)
        return false
    }
}

