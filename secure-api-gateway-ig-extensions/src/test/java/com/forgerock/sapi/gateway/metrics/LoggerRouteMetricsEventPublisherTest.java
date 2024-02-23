/*
 * Copyright © 2020-2024 ForgeRock AS (obst@forgerock.com)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.forgerock.sapi.gateway.metrics;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doNothing;

import java.util.Map;
import java.util.UUID;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.slf4j.Logger;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

@ExtendWith(MockitoExtension.class)
class LoggerRouteMetricsEventPublisherTest {

    @Mock
    private Logger logger;

    @InjectMocks
    private LoggerRouteMetricsEventPublisher loggerRouteMetricPublisher;

    @Test
    void testPublishAsJson() throws JsonProcessingException {
        final RouteMetricsEvent routeMetricsEvent = new RouteMetricsEvent();
        routeMetricsEvent.setEventType("test-event");
        routeMetricsEvent.setRouteId("test-route-id");
        routeMetricsEvent.setContext(Map.of("extraField1", "value1", "extraField2", 2));
        routeMetricsEvent.setHttpMethod("GET");
        routeMetricsEvent.setRequestPath("/test/metrics");
        routeMetricsEvent.setResponseTimeMillis(344334);
        routeMetricsEvent.setSuccessResponse(true);
        routeMetricsEvent.setHttpStatusCode(201);
        routeMetricsEvent.setApiClientId("api-client-1");
        routeMetricsEvent.setApiClientOrgId("api-client-org-1");
        routeMetricsEvent.setSoftwareId("EFxdsfrt23423");
        routeMetricsEvent.setTimestamp(100000);
        routeMetricsEvent.setTrustedDirectory("OpenBankingUK");
        routeMetricsEvent.setFapiInteractionId(UUID.randomUUID().toString());

        ArgumentCaptor<String> jsonArgumentCapture = ArgumentCaptor.forClass(String.class);
        doNothing().when(logger).info(anyString(), jsonArgumentCapture.capture());

        loggerRouteMetricPublisher.publish(routeMetricsEvent);

        final String loggedJson = jsonArgumentCapture.getValue();
        final RouteMetricsEvent loggedEvent = new ObjectMapper().readValue(loggedJson, RouteMetricsEvent.class);
        assertThat(loggedEvent).usingRecursiveComparison().isEqualTo(routeMetricsEvent);
    }

    @Test
    void gracefullyHandlesPublishException() {
        final RouteMetricsEvent routeMetricsEvent = new RouteMetricsEvent();
        // Context allows any data to be plugged into the metrics event, add something which Jackson cannot serialize to trigger an exception
        routeMetricsEvent.setContext(Map.of("extraField1", Runtime.getRuntime()));

        // No Exception is thrown
        loggerRouteMetricPublisher.publish(routeMetricsEvent);
    }
}