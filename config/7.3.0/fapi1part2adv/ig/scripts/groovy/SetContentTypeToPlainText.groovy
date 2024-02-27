
def fapiInteractionId = request.getHeaders().getFirst("x-fapi-interaction-id");
if(fapiInteractionId == null) fapiInteractionId = "No x-fapi-interaction-id";
SCRIPT_NAME = "[SetContentTypeToPlainText] (" + fapiInteractionId + ") - ";

logger.debug(SCRIPT_NAME + "Running...")

def response = new Response(Status.OK);
response.setEntity(contexts.jwtBuilder.value);
response.getHeaders().add("Content-Type","text/plain");

return response