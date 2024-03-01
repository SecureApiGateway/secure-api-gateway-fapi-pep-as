SCRIPT_NAME = "[ExampleRsApiResponseHandler] "
logger.debug(SCRIPT_NAME + "Creating example API response...")

// Example response - return some data from the access_token
Response response = new Response(Status.OK)
var sub = contexts.oauth2.accessToken.info["sub"]
response.entity.json = json(object(field("user", sub)))

return response