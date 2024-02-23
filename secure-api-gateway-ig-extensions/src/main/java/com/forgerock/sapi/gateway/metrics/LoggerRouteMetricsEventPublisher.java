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

import java.io.IOException;
import java.nio.charset.StandardCharsets;

import org.forgerock.http.util.Json;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Implementation of {@link RouteMetricsEventPublisher} which publishes metrics to a {@link org.slf4j.Logger}
 * <p>
 * The publisher passes raw json to the logger, therefore it is recommended to configure the Logger for this class
 * to use an appender which does not apply any decoration to messages.
 * <p>
 * Example logback config:
 * <pre>
 * {@code
 * <appender name="METRICS" class="ch.qos.logback.core.ConsoleAppender">
 *     <encoder>
 *         <pattern>%msg%n</pattern>
 *     </encoder>
 * </appender>
 * <logger name="com.forgerock.sapi.gateway.metrics.LoggerRouteMetricsEventPublisher" additivity="false">
 *      <appender-ref ref="METRICS" />
 * </logger>
 * }
 * </pre>
 */
public class LoggerRouteMetricsEventPublisher implements RouteMetricsEventPublisher {

    /**
     * Logger to write the {@link RouteMetricsEvent}s to
     */
    private final Logger metricsLogger;

    /**
     * Logger for errors produced writing metrics.
     * This is needed in order to keep error messages separate from the actual metrics.
     */
    private final Logger errorLogger = LoggerFactory.getLogger(LoggerRouteMetricsEventPublisher.class.getSimpleName() + "-error");

    public LoggerRouteMetricsEventPublisher() {
        this(LoggerFactory.getLogger(LoggerRouteMetricsEventPublisher.class));
    }

    public LoggerRouteMetricsEventPublisher(Logger metricsLogger) {
        this.metricsLogger = metricsLogger;
    }

    @Override
    public void publish(RouteMetricsEvent routeMetricsEvent) {
        try {
            metricsLogger.info("{}", new String(Json.writeJson(routeMetricsEvent), StandardCharsets.UTF_8));
        } catch (IOException e) {
            errorLogger.error("Json.writeJson failed due to exception", e);
        }
    }
}
