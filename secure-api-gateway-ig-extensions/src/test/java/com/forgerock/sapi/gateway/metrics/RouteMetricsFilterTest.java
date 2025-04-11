/*
 * Copyright © 2020-2025 ForgeRock AS (obst@forgerock.com)
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

import static java.lang.Boolean.FALSE;
import static java.lang.Boolean.TRUE;
import static org.assertj.core.api.Assertions.assertThat;
import static org.forgerock.json.JsonValue.json;
import static org.forgerock.json.JsonValue.object;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.net.URISyntaxException;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;
import java.util.stream.Stream;

import org.forgerock.http.header.GenericHeader;
import org.forgerock.http.protocol.Request;
import org.forgerock.http.protocol.Response;
import org.forgerock.http.protocol.Status;
import org.forgerock.json.JsonValue;
import org.forgerock.json.jose.jwk.JWKSet;
import org.forgerock.json.jose.jws.JwsHeader;
import org.forgerock.json.jose.jws.SignedJwt;
import org.forgerock.json.jose.jwt.JwtClaimsSet;
import org.forgerock.openig.fapi.apiclient.ApiClient;
import org.forgerock.openig.fapi.apiclient.ApiClientOrganisation;
import org.forgerock.openig.fapi.context.FapiContext;
import org.forgerock.openig.handler.router.RoutingContext;
import org.forgerock.openig.heap.HeapImpl;
import org.forgerock.openig.heap.Name;
import org.forgerock.services.context.AttributesContext;
import org.forgerock.services.context.Context;
import org.forgerock.services.context.RootContext;
import org.forgerock.util.promise.NeverThrowsException;
import org.forgerock.util.promise.Promise;
import org.forgerock.util.promise.Promises;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import com.forgerock.sapi.gateway.dcr.filter.FetchApiClientFilter;
import com.forgerock.sapi.gateway.metrics.RouteMetricsFilter.Heaplet;
import com.forgerock.sapi.gateway.util.TestHandlers.FixedResponseHandler;
import com.forgerock.sapi.gateway.util.TestHandlers.TestSuccessResponseHandler;
import com.google.common.base.Ticker;

@ExtendWith(MockitoExtension.class)
class RouteMetricsFilterTest {

    public static final String TRUSTED_DIRECTORY_NAME = "OpenBankingUK";
    private static final ApiClient TEST_API_CLIENT =
            ApiClient.builder()
                     .clientName("Test Client")
                     .oAuth2ClientId(UUID.randomUUID().toString())
                     .organisation(new ApiClientOrganisation(UUID.randomUUID().toString(), "Test Company"))
                     .softwareId(UUID.randomUUID().toString())
                     .softwareStatementAssertion(new SignedJwt(new JwsHeader(),
                                                               new JwtClaimsSet(Map.of("iss", "OpenBankingUK")),
                                                               new byte[0],
                                                               new byte[0]))
                     .roles(List.of())
                     .withEmbeddedJwksSupplier(new JWKSet())
                     .build();

    private static final String TEST_ROUTE_ID = "01-test-route";
    private static final Map<String, Object> EMPTY_METRICS_CONTEXT = Map.of();
    private static final String TEST_FAPI_INTERACTION_ID = UUID.randomUUID().toString();

    @Mock
    private RouteMetricsEventPublisher routeMetricsEventPublisher;

    @Mock
    private Ticker ticker;

    private long timestampSourceInitialValue;

    private AtomicLong timestampSource;

    @BeforeEach
    public void before() {
        timestampSourceInitialValue = System.currentTimeMillis();
        timestampSource = new AtomicLong(timestampSourceInitialValue);
    }

    @Test
    void reportsRouteMetricsForSuccessResponse() throws Exception {
        final long expectedResponseTime = 123L;
        mockTickerForSingleResponseTime(expectedResponseTime);
        final RouteMetricsFilter routeMetricsFilter = createFilter(timestampSource);

        final String method = "POST";
        final String url = "https://localhost/test/route";
        final Request request = createRequest(url, method);

        final ArgumentCaptor<RouteMetricsEvent> metricsEventCaptor = ArgumentCaptor.forClass(RouteMetricsEvent.class);
        doNothing().when(routeMetricsEventPublisher).publish(metricsEventCaptor.capture());

        final TestSuccessResponseHandler handler = new TestSuccessResponseHandler();
        final Promise<Response, NeverThrowsException> responsePromise = routeMetricsFilter.filter(createContext(), request, handler);
        final Response response = responsePromise.getOrThrow(1, TimeUnit.SECONDS);

        assertThat(handler.hasBeenInteractedWith()).isTrue();
        assertThat(response.getStatus().isSuccessful()).isTrue();
        final List<RouteMetricsEvent> metricsEvents = metricsEventCaptor.getAllValues();
        assertThat(metricsEvents.size()).isEqualTo(1);
        final RouteMetricsEvent metricsEvent = metricsEvents.get(0);

        validateMetricsEvent(metricsEvent, timestampSourceInitialValue, expectedResponseTime,
                "POST", "/test/route", 200, true, EMPTY_METRICS_CONTEXT);
    }

    private static Request createRequest(String url, String method) throws URISyntaxException {
        final Request request = new Request();
        request.setUri(url);
        request.setMethod(method);
        request.addHeaders(new GenericHeader("x-fapi-interaction-id", TEST_FAPI_INTERACTION_ID));
        return request;
    }

    @Test
    void reportsRouteMetricsForErrorResponse() throws Exception {
        final long expectedResponseTime = 233;
        mockTickerForSingleResponseTime(expectedResponseTime);
        final RouteMetricsFilter routeMetricsFilter = createFilter(timestampSource);

        final Request request = createRequest("https://localhost/test/route/with/error", "GET");

        final ArgumentCaptor<RouteMetricsEvent> metricsEventCaptor = ArgumentCaptor.forClass(RouteMetricsEvent.class);
        doNothing().when(routeMetricsEventPublisher).publish(metricsEventCaptor.capture());

        final FixedResponseHandler handler = new FixedResponseHandler(new Response(Status.BAD_REQUEST));
        final Promise<Response, NeverThrowsException> responsePromise = routeMetricsFilter.filter(createContext(), request, handler);
        final Response response = responsePromise.getOrThrow(1, TimeUnit.SECONDS);

        assertThat(handler.hasBeenInteractedWith()).isTrue();
        assertThat(response.getStatus().isSuccessful()).isFalse();
        final List<RouteMetricsEvent> metricsEvents = metricsEventCaptor.getAllValues();
        assertThat(metricsEvents.size()).isEqualTo(1);
        final RouteMetricsEvent metricsEvent = metricsEvents.get(0);

        validateMetricsEvent(metricsEvent, timestampSourceInitialValue, expectedResponseTime,
                "GET", "/test/route/with/error", 400, false, EMPTY_METRICS_CONTEXT);
    }

    // Failure to publish the metrics must not result in an error HTTP Response
    @Test
    void gracefullyHandlesMetricsPublisherFailure() throws Exception {
        final long expectedResponseTime = 123L;
        mockTickerForSingleResponseTime(expectedResponseTime);
        final RouteMetricsFilter routeMetricsFilter = createFilter(timestampSource);

        final Request request = createRequest("https://localhost/test/route", "POST");

        doThrow(new IllegalStateException("publisher failed!")).when(routeMetricsEventPublisher).publish(any());

        final TestSuccessResponseHandler handler = new TestSuccessResponseHandler();
        final Promise<Response, NeverThrowsException> responsePromise = routeMetricsFilter.filter(createContext(), request, handler);
        final Response response = responsePromise.getOrThrow(1, TimeUnit.SECONDS);

        assertThat(handler.hasBeenInteractedWith()).isTrue();
        assertThat(response.getStatus().isSuccessful()).isTrue();
    }

    @Test
    void reportsCustomMetricsContextInformation() throws Exception {
        final long expectedResponseTime = 123L;
        mockTickerForSingleResponseTime(expectedResponseTime);

        final Map<String, Object> customMetricsContextData = Map.of("customInfo", 123, "field2", "value2");
        final MetricsContextSupplier customMetricsContextSupplier = (context, request) -> Promises.newResultPromise(customMetricsContextData);
        final RouteMetricsFilter routeMetricsFilter = createFilter(timestampSource, customMetricsContextSupplier);

        final Request request = createRequest("https://localhost/test/route", "POST");

        final ArgumentCaptor<RouteMetricsEvent> metricsEventCaptor = ArgumentCaptor.forClass(RouteMetricsEvent.class);
        doNothing().when(routeMetricsEventPublisher).publish(metricsEventCaptor.capture());

        final TestSuccessResponseHandler handler = new TestSuccessResponseHandler();
        final Promise<Response, NeverThrowsException> responsePromise = routeMetricsFilter.filter(createContext(), request, handler);
        final Response response = responsePromise.getOrThrow(1, TimeUnit.SECONDS);

        assertThat(handler.hasBeenInteractedWith()).isTrue();
        assertThat(response.getStatus().isSuccessful()).isTrue();
        final List<RouteMetricsEvent> metricsEvents = metricsEventCaptor.getAllValues();
        assertThat(metricsEvents.size()).isEqualTo(1);
        final RouteMetricsEvent metricsEvent = metricsEvents.get(0);

        validateMetricsEvent(metricsEvent, timestampSourceInitialValue, expectedResponseTime,
                "POST", "/test/route", 200, true, customMetricsContextData);
    }

    @ParameterizedTest
    @MethodSource("createBuggyMetricsContextSuppliers")
    void gracefullyHandlesMetricsContextSupplierFailure(MetricsContextSupplier buggyMetricsContextSupplier) throws Exception {
        final long expectedResponseTime = 123L;
        mockTickerForSingleResponseTime(expectedResponseTime);
        final RouteMetricsFilter routeMetricsFilter = createFilter(timestampSource, buggyMetricsContextSupplier);

        final Request request = createRequest("https://localhost/test/route", "POST");

        final ArgumentCaptor<RouteMetricsEvent> metricsEventCaptor = ArgumentCaptor.forClass(RouteMetricsEvent.class);
        doNothing().when(routeMetricsEventPublisher).publish(metricsEventCaptor.capture());

        final TestSuccessResponseHandler handler = new TestSuccessResponseHandler();
        final Promise<Response, NeverThrowsException> responsePromise = routeMetricsFilter.filter(createContext(), request, handler);
        final Response response = responsePromise.getOrThrow(1, TimeUnit.SECONDS);

        assertThat(handler.hasBeenInteractedWith()).isTrue();
        assertThat(response.getStatus().isSuccessful()).isTrue();
        final List<RouteMetricsEvent> metricsEvents = metricsEventCaptor.getAllValues();
        assertThat(metricsEvents.size()).isEqualTo(1);
        final RouteMetricsEvent metricsEvent = metricsEvents.get(0);

        validateMetricsEvent(metricsEvent, timestampSourceInitialValue, expectedResponseTime,
                "POST", "/test/route", 200, true, EMPTY_METRICS_CONTEXT);
    }

    static Stream<Arguments> createBuggyMetricsContextSuppliers() {
        return Stream.of(
                Arguments.of(
                        (MetricsContextSupplier) (requestContext, request) -> {
                            throw new IllegalStateException("boom");
                        }
                ),
                Arguments.of(
                        (MetricsContextSupplier) (requestContext, request) -> Promises.newRuntimeExceptionPromise(new IllegalStateException("boom"))
                ));
    }

    @Test
    void shouldUseNullIfApiClientIsMissing() throws Exception {
        final long expectedResponseTime = 233;
        mockTickerForSingleResponseTime(expectedResponseTime);
        final RouteMetricsFilter routeMetricsFilter = createFilter(timestampSource);

        final Request request = createRequest("https://localhost/test/route/with/error", "GET");

        final ArgumentCaptor<RouteMetricsEvent> metricsEventCaptor = ArgumentCaptor.forClass(RouteMetricsEvent.class);
        doNothing().when(routeMetricsEventPublisher).publish(metricsEventCaptor.capture());

        final FixedResponseHandler handler = new FixedResponseHandler(new Response(Status.BAD_REQUEST));
        final Promise<Response, NeverThrowsException> responsePromise = routeMetricsFilter.filter(
                createContext(null), request, handler);
        final Response response = responsePromise.getOrThrow(1, TimeUnit.SECONDS);

        assertThat(handler.hasBeenInteractedWith()).isTrue();
        assertThat(response.getStatus().isSuccessful()).isFalse();
        final List<RouteMetricsEvent> metricsEvents = metricsEventCaptor.getAllValues();
        assertThat(metricsEvents.size()).isEqualTo(1);
        final RouteMetricsEvent metricsEvent = metricsEvents.get(0);

        validateMetricsEventCoreFields(metricsEvent, timestampSourceInitialValue, expectedResponseTime,
                "GET", "/test/route/with/error", 400, false, EMPTY_METRICS_CONTEXT);
        assertThat(metricsEvent.getApiClientId()).isEqualTo(null);
        assertThat(metricsEvent.getApiClientOrgId()).isEqualTo(null);
        assertThat(metricsEvent.getTrustedDirectory()).isEqualTo(null);
    }

    @Test
    void testSuccessResponseStatusMappings() {
        Map<Status, Boolean> statusToSuccessResponse = Map.of(
                Status.OK, TRUE,
                Status.CREATED, TRUE,
                Status.NO_CONTENT, TRUE,
                Status.CONTINUE, TRUE,
                Status.FOUND, TRUE,
                Status.BAD_REQUEST, FALSE,
                Status.UNAUTHORIZED, FALSE,
                Status.FORBIDDEN, FALSE,
                Status.INTERNAL_SERVER_ERROR, FALSE,
                Status.BAD_GATEWAY, FALSE);

        statusToSuccessResponse.forEach((status, expectedResult) ->
                assertThat(RouteMetricsFilter.isSuccessResponse(status)).isEqualTo(expectedResult));
    }

    @Test
    void testGetApiClientId() {
        assertThat(RouteMetricsFilter.getApiClientId(TEST_API_CLIENT)).isEqualTo(TEST_API_CLIENT.getOAuth2ClientId());
        assertThat(RouteMetricsFilter.getApiClientId(null)).isEqualTo(null);
    }

    @Test
    void testGetApiClientOrgId() {
        assertThat(RouteMetricsFilter.getApiClientOrgId(TEST_API_CLIENT)).isEqualTo(TEST_API_CLIENT.getOrganisation().id());
        assertThat(RouteMetricsFilter.getApiClientOrgId(mock(ApiClient.class))).isEqualTo(null);
        assertThat(RouteMetricsFilter.getApiClientOrgId(null)).isEqualTo(null);
    }

    @Test
    void testGetTrustedDirectory() {
        assertThat(RouteMetricsFilter.getTrustedDirectory(TEST_API_CLIENT))
                .isEqualTo(TEST_API_CLIENT.getSoftwareStatementAssertion().getClaimsSet().getIssuer());
        assertThat(RouteMetricsFilter.getTrustedDirectory(null)).isEqualTo(null);
    }

    private static Context createContext() {
        return createContext(TEST_API_CLIENT);
    }

    private static Context createContext(ApiClient apiClient) {
        final AttributesContext attributesContext = new AttributesContext(new RootContext());
        FapiContext fapiContext = new FapiContext(attributesContext);
        if (apiClient != null) {
            fapiContext.setApiClient(apiClient);
        }
        return new RoutingContext(fapiContext, RouteMetricsFilterTest.TEST_ROUTE_ID, "test-route-name");
    }

    private void mockTickerForSingleResponseTime(long responseTimeMillis) {
        when(ticker.read()).thenReturn(0L, TimeUnit.MILLISECONDS.toNanos(responseTimeMillis));
    }

    private static void validateMetricsEvent(RouteMetricsEvent metricsEvent, long expectedTimestamp,
            long expectedResponseTime, String expectedHttpMethod, String expectedRequestPath,
            int expectedStatusCode, boolean isSuccessResponse, Map<String, Object> expectedMetricsContext) {

        validateMetricsEventCoreFields(metricsEvent, expectedTimestamp, expectedResponseTime, expectedHttpMethod,
                expectedRequestPath, expectedStatusCode, isSuccessResponse, expectedMetricsContext);
        assertThat(metricsEvent.getApiClientId()).isEqualTo(TEST_API_CLIENT.getOAuth2ClientId());
        assertThat(metricsEvent.getApiClientOrgId()).isEqualTo(TEST_API_CLIENT.getOrganisation().id());
        assertThat(metricsEvent.getSoftwareId()).isEqualTo(TEST_API_CLIENT.getSoftwareId());
        assertThat(metricsEvent.getTrustedDirectory()).isEqualTo(TRUSTED_DIRECTORY_NAME);
        assertThat(metricsEvent.getFapiInteractionId()).isEqualTo(TEST_FAPI_INTERACTION_ID);
    }

    private static void validateMetricsEventCoreFields(RouteMetricsEvent metricsEvent, long expectedTimestamp,
            long expectedResponseTime, String expectedHttpMethod, String expectedRequestPath,
            int expectedStatusCode, boolean isSuccessResponse, Map<String, Object> expectedMetricsContext) {

        assertThat(metricsEvent.getRouteId()).isEqualTo(TEST_ROUTE_ID);
        assertThat(metricsEvent.getEventType()).isEqualTo("route-metrics");
        assertThat(metricsEvent.getHttpMethod()).isEqualTo(expectedHttpMethod);
        assertThat(metricsEvent.getRequestPath()).isEqualTo(expectedRequestPath);
        assertThat(metricsEvent.getContext()).isEqualTo(expectedMetricsContext);
        assertThat(metricsEvent.getHttpStatusCode()).isEqualTo(expectedStatusCode);
        assertThat(metricsEvent.isSuccessResponse()).isEqualTo(isSuccessResponse);
        assertThat(metricsEvent.getTimestamp()).isEqualTo(expectedTimestamp);
        assertThat(metricsEvent.getResponseTimeMillis()).isEqualTo(expectedResponseTime);
    }

    private RouteMetricsFilter createFilter(AtomicLong timestampSource) {
        return new RouteMetricsFilter(ticker, timestampSource::getAndIncrement,
                                      routeMetricsEventPublisher,
                                      MetricsContextSupplier.EMPTY_CONTEXT_SUPPLIER);
    }

    private RouteMetricsFilter createFilter(AtomicLong timestampSource, MetricsContextSupplier metricsContextSupplier) {
        return new RouteMetricsFilter(ticker, timestampSource::getAndIncrement,
                routeMetricsEventPublisher,
                metricsContextSupplier);
    }



    @Nested
    public class HeapletTests {

        @Test
        void testHeapletCreatedRouteMetricsFilter() throws Exception {
            final JsonValue config = json(object());
            final HeapImpl heap = new HeapImpl(Name.of("heap"));
            final RouteMetricsFilter routeMetricsFilter = (RouteMetricsFilter) new Heaplet().create(Name.of("test"), config, heap);
            final Request request = createRequest("https://localhost/test/example", "GET");

            final TestSuccessResponseHandler handler = new TestSuccessResponseHandler();
            final Promise<Response, NeverThrowsException> responsePromise = routeMetricsFilter.filter(createContext(), request, handler);
            final Response response = responsePromise.getOrThrow(1, TimeUnit.SECONDS);

            assertThat(handler.hasBeenInteractedWith()).isTrue();
            assertThat(response.getStatus().isSuccessful()).isTrue();

            // The heaplet produces a filter which uses a LoggerRouteMetricsEventPublisher, see log file for the output
        }

    }
}