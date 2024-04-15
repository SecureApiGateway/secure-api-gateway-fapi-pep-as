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

import static org.forgerock.openig.util.JsonValues.optionalHeapObject;
import static org.forgerock.util.Reject.checkNotNull;

import java.util.Collections;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import java.util.function.LongSupplier;

import org.forgerock.http.Filter;
import org.forgerock.http.Handler;
import org.forgerock.http.protocol.Request;
import org.forgerock.http.protocol.Response;
import org.forgerock.http.protocol.Status;
import org.forgerock.openig.handler.router.RoutingContext;
import org.forgerock.openig.heap.GenericHeaplet;
import org.forgerock.openig.heap.HeapException;
import org.forgerock.services.context.Context;
import org.forgerock.util.promise.NeverThrowsException;
import org.forgerock.util.promise.Promise;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.forgerock.sapi.gateway.dcr.filter.FetchApiClientFilter;
import com.forgerock.sapi.gateway.dcr.models.ApiClient;
import com.forgerock.sapi.gateway.fapi.FapiUtils;
import com.forgerock.sapi.gateway.trusteddirectories.TrustedDirectoryService;
import com.google.common.base.Stopwatch;
import com.google.common.base.Ticker;

/**
 * This filter is responsible for reporting metrics for the route that it is configured in. The metrics are published as
 * {@link RouteMetricsEvent} objects, with one event being published per request processed by the route.
 * <p>
 * The filter should be installed as the first filter in the chain in order to get the most accurate response time data.
 * <p>
 * {@link RouteMetricsEvent} objects contain {@link ApiClient} metadata, this filter expects to find the ApiClient in
 * the attributes context in the response path. This means that the attributes context needs to be populated correctly
 * prior to this filter processing the response, typically this involves running the {@link FetchApiClientFilter}.
 */
public class RouteMetricsFilter implements Filter {

    private final Logger logger = LoggerFactory.getLogger(getClass());

    /**
     * Ticker is a nanosecond time source which is used to measure the response time using a {@link Stopwatch}
     * See {@link Stopwatch#createStarted(Ticker)}
     */
    private final Ticker ticker;

    /**
     * Supplier of millisecond precision unix epoch timestamps
     */
    private final LongSupplier timestampSupplier;

    /**
     * Publisher of {@link RouteMetricsEvent} objects produced by this filter
     */
    private final RouteMetricsEventPublisher metricsEventPublisher;

    /**
     * Supplier of Metrics Context information which is extracted from the HTTP Request being processed
     */
    private final MetricsContextSupplier metricsContextSupplier;

    public RouteMetricsFilter(Ticker ticker, LongSupplier timestampSupplier,
                              RouteMetricsEventPublisher metricsEventPublisher,
                              MetricsContextSupplier metricsContextSupplier) {
        this.ticker = checkNotNull(ticker, "ticker must be provided");
        this.timestampSupplier = checkNotNull(timestampSupplier, "timestampSupplier must be provided");
        this.metricsEventPublisher = checkNotNull(metricsEventPublisher, "metricsEventPublisher must be provided");
        this.metricsContextSupplier = checkNotNull(metricsContextSupplier, "metricsContextSupplier must be provided");
    }

    @Override
    public Promise<Response, NeverThrowsException> filter(Context context, Request request, Handler handler) {
        final Stopwatch stopwatch = Stopwatch.createStarted(ticker);
        final Map<String, Object> routeMetricsContext = getRouteMetricsContext(context, request);
        return handler.handle(context, request).thenOnResult(response -> {
            try {
                metricsEventPublisher.publish(buildRouteMetricsEvent(stopwatch, context, request, response, routeMetricsContext));
            } catch (RuntimeException ex) {
                logger.error("Failed to publish metrics due to exception", ex);
            }
        });
    }

    private RouteMetricsEvent buildRouteMetricsEvent(Stopwatch stopwatch, Context context, Request request,
                                                     Response response, Map<String, Object> metricsContext) {
        final ApiClient apiClient = FetchApiClientFilter.getApiClientFromContext(context);

        final RouteMetricsEvent metricEvent = new RouteMetricsEvent();
        metricEvent.setTimestamp(timestampSupplier.getAsLong());
        metricEvent.setContext(metricsContext);
        metricEvent.setEventType("route-metrics");
        metricEvent.setRouteId(getRouteId(context));
        metricEvent.setHttpMethod(request.getMethod());
        metricEvent.setRequestPath(request.getUri().getPath());
        metricEvent.setApiClientId(getApiClientId(apiClient));
        metricEvent.setApiClientOrgId(getApiClientOrgId(apiClient));
        metricEvent.setSoftwareId(getSoftwareId(apiClient));
        metricEvent.setTrustedDirectory(getTrustedDirectory(apiClient));
        metricEvent.setHttpStatusCode(response.getStatus().getCode());
        metricEvent.setSuccessResponse(isSuccessResponse(response.getStatus()));

        FapiUtils.getFapiInteractionId(request).ifPresent(metricEvent::setFapiInteractionId);

        stopwatch.stop();
        metricEvent.setResponseTimeMillis(stopwatch.elapsed(TimeUnit.MILLISECONDS));
        return metricEvent;
    }

    private Map<String, Object> getRouteMetricsContext(Context context, Request request) {
        try {
            final Map<String, Object> metricsContext = metricsContextSupplier.getMetricsContext(context, request);
            if (metricsContext != null) {
                return metricsContext;
            }
        } catch (RuntimeException ex) {
            logger.error("Unexpected exception thrown invoking metricsContextSupplier", ex);
        }
        return Collections.emptyMap();
    }

    /**
     * @param responseStatus Status of the Response object
     * @return boolean which indicates whether the Response is deemed a success or not. A success is any response that
     * is not a 4xx or 5xx.
     */
    static boolean isSuccessResponse(Status responseStatus) {
        return !(responseStatus.isClientError() || responseStatus.isServerError());
    }

    static String getApiClientId(ApiClient apiClient) {
        if (apiClient == null) {
            return null;
        } else {
            return apiClient.getOAuth2ClientId();
        }
    }

    static String getApiClientOrgId(ApiClient apiClient) {
        if (apiClient == null) {
            return null;
        } else {
            if (apiClient.getOrganisation() == null) {
                return null;
            } else {
                return apiClient.getOrganisation().id();
            }
        }
    }

    static String getSoftwareId(ApiClient apiClient ) {
        if (apiClient == null) {
            return null;
        } else {
            return apiClient.getSoftwareClientId();
        }
    }

    static String getTrustedDirectory(ApiClient apiClient) {
        if (apiClient == null) {
            return null;
        } else {
            return TrustedDirectoryService.getTrustedDirectoryIssuerName(apiClient);
        }
    }

    private static String getRouteId(Context context) {
        return context.as(RoutingContext.class)
                      .map(RoutingContext::getRouteId)
                      .orElse(null);
    }

    /**
     * Heaplet responsible for constructing {@link RouteMetricsFilter}
     * <p>
     * Optional config:
     * <p>
     * - metricsContextSupplier an instance of {@link MetricsContextSupplier} found on the heap, this extracts custom
     *                          request specific metrics contextual information. Example implementation: {@link TokenEndpointMetricsContextSupplier}
     *                          Defaults to: MetricsContextSupplier.EMPTY_CONTEXT_SUPPLIER which supplies no context information
     * <pre>
     * Example config:
     * {
     *             "name": "RouteMetricsFilter",
     *             "type": "RouteMetricsFilter",
     *             "comment": "Filter for reporting request metrics to the log file"
     * }
     * </pre>
     */
    public static class Heaplet extends GenericHeaplet {

        @Override
        public Object create() throws HeapException {

            MetricsContextSupplier metricsContextSupplier = config.get("metricsContextSupplier")
                                                                  .as(optionalHeapObject(heap, MetricsContextSupplier.class));
            if (metricsContextSupplier == null) {
                metricsContextSupplier = MetricsContextSupplier.EMPTY_CONTEXT_SUPPLIER;
            }

            return new RouteMetricsFilter(Ticker.systemTicker(),
                                          System::currentTimeMillis,
                                          new LoggerRouteMetricsEventPublisher(),
                                          metricsContextSupplier);
        }
    }
}
