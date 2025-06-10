/**
 * Workaround for AM issue: https://bugster.forgerock.org/jira/browse/OPENAM-21910
 * AM is expecting that the client_id is always supplied as a parameter when calling the /par endpoint.
 *
 * This should only be the case when the client_id is needed to authenticate the client i.e. when doing tls_client_auth,
 * for other auth methods, such as private_key_jwt, the client_id should not be supplied.
 *
 * This filter adds the client_id param if it is missing, sourcing the value from the request JWT param's iss claim.
 */
SCRIPT_NAME = "XXX [DebugLogging]"

logger.debug("{} request: method={}, uri={}, params=",
             SCRIPT_NAME,
             request.getMethod(),
             request.getUri(),
             request.getQueryParams().toQueryString())
return next.handle(context, request)
           .then(response -> {
               response.getEntity()
                       .getJsonAsync()
                       .then(JsonValue::new)
                       .then(json -> {
                           logger.debug("{} response: entity={} | request: method={}, uri={}, params={}",
                                        SCRIPT_NAME,
                                        json,
                                        request.getMethod(),
                                        request.getUri(),
                                        request.getQueryParams().toQueryString())
                           return response;
                       });
           });

