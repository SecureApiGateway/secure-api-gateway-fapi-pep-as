/**
 * Workaround for AM issue: https://bugster.forgerock.org/jira/browse/OPENAM-21910
 * AM is expecting that the client_id is always supplied as a parameter when calling the /par endpoint.
 *
 * This should only be the case when the client_id is needed to authenticate the client i.e. when doing tls_client_auth,
 * for other auth methods, such as private_key_jwt, the client_id should not be supplied.
 *
 * This filter adds the client_id param if it is missing, sourcing the value from the request JWT param's iss claim.
 */

import static org.forgerock.http.protocol.Response.newResponsePromise

SCRIPT_NAME = "XXX [DebugLogging]"

logger.debug("{} request: method={}, uri={}, params={}",
             SCRIPT_NAME,
             request.getMethod(),
             request.getUri(),
             request.getQueryParams().toQueryString())
return next.handle(context, request)
           .thenAsync(response -> {
               List<String> mediaTypes = response.getHeaders().getAll(ContentTypeHeader.NAME);
               if (mediaTypes.stream().anyMatch(mediaType -> mediaType.startsWith("application/json"))) {
                   return response.getEntity()
                                  .getJsonAsync()
                                  .then(JsonValue::new)
                                  .thenAsync(json -> {
                                      logger.debug("{} response: entity-json={} | request: method={}, uri={}, params={}",
                                                   SCRIPT_NAME,
                                                   json,
                                                   request.getMethod(),
                                                   request.getUri(),
                                                   request.getQueryParams().toQueryString())
                                      return newResponsePromise(response)
                                  })
               }
               return response.getEntity()
                              .getStringAsync()
                              .thenAsync(error -> {
                                  logger.debug("{} response: entity={} | request: method={}, uri={}, params={}",
                                               SCRIPT_NAME,
                                               error,
                                               request.getMethod(),
                                               request.getUri(),
                                               request.getQueryParams().toQueryString())
                                  return newResponsePromise(response)
                              })
           })
