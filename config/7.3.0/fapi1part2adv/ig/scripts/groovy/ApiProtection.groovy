
def fapiInteractionId = request.getHeaders().getFirst("x-fapi-interaction-id");
if(fapiInteractionId == null) fapiInteractionId = "No x-fapi-interaction-id"
SCRIPT_NAME = "[ApiProtection] (" + fapiInteractionId + ") - "

logger.debug(SCRIPT_NAME + "Running...")

next.handle(context, request)