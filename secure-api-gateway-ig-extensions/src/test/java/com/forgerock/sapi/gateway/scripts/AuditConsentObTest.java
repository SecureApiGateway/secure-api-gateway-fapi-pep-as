package com.forgerock.sapi.gateway.scripts;

import static java.util.Arrays.asList;
import static java.util.Collections.singletonList;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.InstanceOfAssertFactories.type;
import static org.forgerock.audit.AuditServiceBuilder.newAuditService;
import static org.forgerock.http.protocol.Response.newResponsePromise;
import static org.forgerock.http.protocol.Status.OK;
import static org.forgerock.json.JsonValue.field;
import static org.forgerock.json.JsonValue.json;
import static org.forgerock.json.JsonValue.object;
import static org.forgerock.json.resource.Responses.newResourceResponse;
import static org.forgerock.util.promise.Promises.newResultPromise;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import org.forgerock.json.resource.CreateRequest;
import org.forgerock.services.context.Context;
import org.mockito.ArgumentCaptor;

import java.net.URI;
import java.time.Clock;
import java.time.Instant;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;

import org.forgerock.audit.AuditException;
import org.forgerock.audit.AuditService;
import org.forgerock.audit.AuditServiceConfiguration;
import org.forgerock.audit.filter.FilterPolicy;
import org.forgerock.audit.handlers.json.JsonAuditEventHandlerConfiguration;
import org.forgerock.http.Filter;
import org.forgerock.http.Handler;
import org.forgerock.http.protocol.Request;
import org.forgerock.http.protocol.Response;
import org.forgerock.json.JsonValue;
import org.forgerock.json.resource.ServiceUnavailableException;
import org.forgerock.openig.filter.ScriptableFilter;
import org.forgerock.openig.heap.HeapImpl;
import org.forgerock.openig.heap.Name;
import org.forgerock.services.TransactionId;
import org.forgerock.services.context.AttributesContext;
import org.forgerock.services.context.RootContext;
import org.forgerock.services.context.TransactionIdContext;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Captor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.forgerock.audit.handlers.json.JsonAuditEventHandler;

/**
 * Unit test for {@code ProcessRegistration} script.
 */
@ExtendWith(MockitoExtension.class)
public class AuditConsentObTest extends AbstractScriptTest {

    // Values
    private static final Instant NOW = Instant.parse("2025-07-07T09:46:34Z");
    private static final String API_CLIENT_ID = "1234";
    private static final URI REQUEST_URI = URI.create("https://www.bank.com/" + API_CLIENT_ID);

    @Mock
    private Clock clock;
    @Mock
    private AuditService auditService;
    @Mock
    private Handler next;
    @Captor
    private ArgumentCaptor<CreateRequest> createRequestCaptor;

    private AttributesContext context;

    @BeforeEach
    public void setUp() throws AuditException, ServiceUnavailableException {
        context = new AttributesContext(new TransactionIdContext(new RootContext(), new TransactionId("123456")));
        when(clock.instant()).thenReturn(NOW);
        //TODO[using mock]: buildAuditService();
    }

    private void buildAuditService() throws AuditException, ServiceUnavailableException {
        final String name = "JsonAuditEvents";
        final String topic = "access";
        final Class<JsonAuditEventHandler> clazz = JsonAuditEventHandler.class;
        final JsonAuditEventHandlerConfiguration configuration = new JsonAuditEventHandlerConfiguration();
        configuration.setName(name);
        configuration.setTopics(Collections.singleton(topic));
        final AuditService auditService = newAuditService()
                .withConfiguration(getAuditServiceConfiguration(name, topic))
                .withAuditEventHandler(clazz, configuration)
                .build();
        auditService.startup();
    }

    private AuditServiceConfiguration getAuditServiceConfiguration(String queryHandlerName, String topic) {
        final AuditServiceConfiguration config = new AuditServiceConfiguration();
        config.setHandlerForQueries(queryHandlerName);
        config.setAvailableAuditEventHandlers(
                singletonList("org.forgerock.audit.handlers.json.JsonAuditEventHandler"));
        if (topic != null) {
            FilterPolicy filterPolicy = new FilterPolicy();
            // whitelist minimum set of fields required for tests to pass
            filterPolicy.setIncludeIf(asList(
                    "/" + topic + "/eventName",
                    "/" + topic + "/transactionId",
                    "/" + topic + "/timestamp"));
            final Map<String, FilterPolicy> filterPolicies = new LinkedHashMap<>();
            filterPolicies.put("field", filterPolicy);
            config.setFilterPolicies(filterPolicies);
        }
        return config;
    }

    protected HeapImpl getHeap() throws Exception {
        final HeapImpl heap = super.getHeap();
        heap.put("AuditService", auditService);
        heap.put("Clock", clock);
        return heap;
    }

    @Test
    void shouldProcessAuditConsentFromContext() throws Exception {
        // Given
        Request request = new Request().setMethod("POST").setUri(REQUEST_URI);
        context.getAttributes().put("openbanking_intent_id", "some-consent-id");
        when(auditService.handleCreate(any(), any()))
                .thenReturn(newResultPromise(newResourceResponse("DontPanic", "42", json(object()))));
        when(next.handle(context, request))
                .thenReturn(newResponsePromise(new Response(OK).setEntity(json(object()))));
        // ... filter and context
        JsonValue config = validAuditConsentConfig();
        Filter filter = (Filter) new ScriptableFilter.Heaplet()
                .create(Name.of("AuditConsentOB"), config, getHeap());
        // When
        final Response response = filter.filter(context, request, next).get();
        // Then
        assertThat(response.getStatus()).isEqualTo(OK);
        verify(auditService).handleCreate(any(), createRequestCaptor.capture());
        CreateRequest createRequest = createRequestCaptor.getValue();
        assertThat(createRequest.toJsonValue())
                .asInstanceOf(type(JsonValue.class))
                .satisfies(jsonValue -> {
                    assertThat(jsonValue.get("content").get("consent").get("id").asString())
                            .isEqualTo("some-consent-id");
                });
    }

    private JsonValue validAuditConsentConfig() {
        // "auditService": "${heap['AuditService-OB-Consent']}",
        // "clock": "${heap['Clock']}",
        // "consentIdLocator": "contexts.attributes.openbanking_intent_id",
        // "role": "CBPII",
        // "event": "EXEC"
        return json(object(field("type", GROOVY_MIME_TYPE),
                           field("file", "AuditConsentOB.groovy"),
                           field("args",
                                 object(field("auditService", "${heap['AuditService']}"),
                                        field("clock", "${heap['Clock']}"),
                                        // TODO[use-me-to-break-the-script-again] field("consentIdLocator", "contexts.attributes.openbanking_intent_id"),
                                        field("consentIdLocator", "contexts.attributes.attributes.openbanking_intent_id"),
                                        field("role", "CBPII"),
                                        field("event", "EXEC")))));
    }
}
