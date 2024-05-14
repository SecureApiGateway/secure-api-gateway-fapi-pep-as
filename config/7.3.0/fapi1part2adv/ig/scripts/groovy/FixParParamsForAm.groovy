/**
 * Workaround for AM issue: https://bugster.forgerock.org/jira/browse/OPENAM-21910
 * AM is expecting that the client_id is always supplied as a parameter when calling the /par endpoint.
 *
 * This should only be the case when the client_id is needed to authenticate the client i.e. when doing tls_client_auth,
 * for other auth methods, such as private_key_jwt, the client_id should not be supplied.
 *
 * This filter adds the client_id param if it is missing, sourcing the value from the request JWT param's iss claim.
 */

import org.forgerock.json.jose.common.JwtReconstruction
import org.forgerock.json.jose.jws.SignedJwt

SCRIPT_NAME = "[FixParParamsForAm] "
logger.debug(SCRIPT_NAME + "Running...")

def form = request.getEntity().getForm()
if (!form.containsKey("client_id")) {
    addClientIdParamToRequest(form)
}
next.handle(context, request)

private void addClientIdParamToRequest(form) {
    def requestJwtString = form.getFirst("request")
    try {
        def requestJwt = new JwtReconstruction().reconstructJwt(requestJwtString, SignedJwt.class)
        def clientId = requestJwt.getClaimsSet().getIssuer()
        form.add("client_id", clientId)
        logger.debug("{}Adding client_id: {} to request params", SCRIPT_NAME, clientId)
        request.setEntity(form)
    } catch (e) {
        logger.warn(SCRIPT_NAME + "failed to add client_id to request", e)
    }
}

