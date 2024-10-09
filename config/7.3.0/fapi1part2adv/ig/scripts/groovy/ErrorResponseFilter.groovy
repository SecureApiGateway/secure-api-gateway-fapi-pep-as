/**
 * This script is a simple implementation of HTTP Basic Authentication on
 * server side.
 * It expects the following arguments:
 *  - realm: the realm to display when the user-agent prompts for
 *    username and password if none were provided.
 *  - username: the expected username
 *  - password: the expected password
 */
SCRIPT_NAME = "[ErrorResponseFilter] - "

logger.debug(SCRIPT_NAME + "Running...")

class ErrorResponse {
    public String error_description
    public String error
}

return next.handle(context, request).thenOnResult {
    response -> {
        if(response.status.isClientError()){
            logger.debug("{} Response has status {} - which is a Client Error", SCRIPT_NAME, response.status)
            var errorResponse = response.entity.getJson();

            logger.debug("{} Response has body {}", SCRIPT_NAME, errorResponse)
            try {
                ErrorResponse error = (ErrorResponse)errorResponse
                if(error.error_description.equals("code_verifier parameter required")){
                    logger.debug("{} changing error from {} to {}", SCRIPT_NAME, error.error, "invalid_grant")
                    error.error = "invalid_grant"
                    response.entity.setJson((Object)error)
                } else

                if (error.error_description.equals("The redirection URI provided does not match a pre-registered value.")){
                    logger.debug("{} changing error from {} to {}", SCRIPT_NAME, error.error, "invalid_grant")
                    error.error = "invalid_request_object"
                    response.entity.setJson((Object)error)
                }
            } catch (e){
                logger.debug("{} error casting json body to be ErrorResponse. Exception: {}" SCRIPT_NAME, e)
            }
        }
    }
};