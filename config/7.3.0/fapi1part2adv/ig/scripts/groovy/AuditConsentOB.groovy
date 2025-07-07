import static org.forgerock.json.resource.Requests.newCreateRequest;
import static org.forgerock.json.resource.ResourcePath.resourcePath;
//TODO: This is no longer available on this import
//import static com.forgerock.sapi.gateway.rest.HttpHeaderNames.X_FAPI_INTERACTION_ID
X_FAPI_INTERACTION_ID = "x-fapi-interaction-id";

SCRIPT_NAME = "[AuditConsent] - "


// Helper functions
def String transactionId() {
    return contexts.transactionId.transactionId.value;
}

def JsonValue auditEvent(String eventName) {
    return json(object(field('eventName', eventName),
                       field('transactionId', transactionId()),
                       field('timestamp', clock.instant().toEpochMilli())));
}

def auditEventRequest(String topicName, JsonValue auditEvent) {
    return newCreateRequest(resourcePath("/" + topicName), auditEvent);
}

def resourceEvent() {
    return object(field('path', request.uri.path),
                  field('method', request.method));
}


next.handle(context, request).thenOnResult(response -> {
    logger.debug(SCRIPT_NAME + "Running...")
    if (!response.status.isSuccessful()) {
        logger.info(SCRIPT_NAME + "Error response, skipping audit")
        return
    }
    // NO_CONTENT is typically returned by deletes, these are currently not supported as the consentIdLocator will fail
    if (response.status == Status.NO_CONTENT) {
        logger.info(SCRIPT_NAME + "No Content response, skipping audit")
        return
    }

    logger.info(SCRIPT_NAME + context)

    def binding = new Binding()
    binding.response = response
    binding.contexts = contexts
    logger.info(SCRIPT_NAME + "consentIdLocator={}", consentIdLocator)
    consentId = new GroovyShell(binding).evaluate(consentIdLocator)
    logger.info(SCRIPT_NAME + "consentId={} ({})", consentId, consentId.getClass())

    def consent = object(
            field('id', consentId),
            field('role', role)
    )
    // Build the event
    JsonValue auditEvent = auditEvent('OB-CONSENT-' + event).add('consent', consent)

    def fapiInfo = [:]
    def values = request.headers.get(X_FAPI_INTERACTION_ID)
    if (values) {
        fapiInfo.put(X_FAPI_INTERACTION_ID, values.firstValue)
    }

    auditEvent = auditEvent.add('fapiInfo', fapiInfo);

    // Send the event
    auditService.handleCreate(context, auditEventRequest("ObConsentTopic", auditEvent))
    logger.debug(SCRIPT_NAME + "audited event for consentId: " + consentId)
})
