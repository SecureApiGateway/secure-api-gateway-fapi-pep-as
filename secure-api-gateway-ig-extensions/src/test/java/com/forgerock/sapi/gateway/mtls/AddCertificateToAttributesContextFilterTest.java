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
package com.forgerock.sapi.gateway.mtls;

import static com.forgerock.sapi.gateway.mtls.AddCertificateToAttributesContextFilter.DEFAULT_CERTIFICATE_ATTRIBUTE;
import static com.forgerock.sapi.gateway.mtls.HeaderCertificateRetrieverTest.createRequestWithCertHeader;
import static com.forgerock.sapi.gateway.util.CryptoUtils.generateRsaKeyPair;
import static com.forgerock.sapi.gateway.util.CryptoUtils.generateX509Cert;
import static org.assertj.core.api.Assertions.assertThat;
import static org.forgerock.json.JsonValue.json;
import static org.forgerock.json.JsonValue.object;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.IOException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.concurrent.ExecutionException;

import org.forgerock.http.protocol.Request;
import org.forgerock.http.protocol.Response;
import org.forgerock.http.protocol.Status;
import org.forgerock.json.JsonValue;
import org.forgerock.json.JsonValueException;
import org.forgerock.openig.heap.HeapException;
import org.forgerock.openig.heap.HeapImpl;
import org.forgerock.openig.heap.Name;
import org.forgerock.services.TransactionId;
import org.forgerock.services.context.AttributesContext;
import org.forgerock.services.context.Context;
import org.forgerock.services.context.RootContext;
import org.forgerock.services.context.TransactionIdContext;
import org.forgerock.util.promise.NeverThrowsException;
import org.forgerock.util.promise.Promise;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import com.forgerock.sapi.gateway.mtls.AddCertificateToAttributesContextFilter.Heaplet;
import com.forgerock.sapi.gateway.util.TestHandlers.TestSuccessResponseHandler;

class AddCertificateToAttributesContextFilterTest {

    private final X509Certificate testCertificate = generateX509Cert(generateRsaKeyPair(), "CN=test");

    private static class SingletonCertificateRetriever implements CertificateRetriever {
        private final X509Certificate certificate;

        private SingletonCertificateRetriever(X509Certificate certificate) {
            this.certificate = certificate;
        }

        @Override
        public X509Certificate retrieveCertificate(Context context, Request request) {
            return certificate;
        }

        @Override
        public boolean certificateExists(Context context, Request request) {
            return true;
        }
    }

    private static class ExceptionThrowingCertificateRetriever implements CertificateRetriever {

        @Override
        public X509Certificate retrieveCertificate(Context context, Request request) throws CertificateException {
            throw new CertificateException("Cert is invalid");
        }

        @Override
        public boolean certificateExists(Context context, Request request) {
            return true;
        }
    }

    private static Context createContext() {
        return new TransactionIdContext(new AttributesContext(new RootContext()), new TransactionId("tx1234"));
    }

    @Test
    void testCertificateIsAddedToAttributesContext() throws Exception {
        testCertificateIsAddedToAttributesContext(testCertificate, DEFAULT_CERTIFICATE_ATTRIBUTE,
                new AddCertificateToAttributesContextFilter(new SingletonCertificateRetriever(testCertificate), DEFAULT_CERTIFICATE_ATTRIBUTE));
    }

    private void testCertificateIsAddedToAttributesContext(X509Certificate testCertificate, String attributeName, AddCertificateToAttributesContextFilter filter) throws Exception {
        testCertificateIsAddedToAttributesContext(testCertificate, attributeName, filter, new Request());
    }

    private void testCertificateIsAddedToAttributesContext(X509Certificate testCertificate, String attributeName, AddCertificateToAttributesContextFilter filter, Request request) throws Exception {
        final TestSuccessResponseHandler successHandler = new TestSuccessResponseHandler();
        final Context context = createContext();
        final Promise<Response, NeverThrowsException> responsePromise = filter.filter(context, request, successHandler);

        final X509Certificate retrievedCert = getCertFromContext(context, attributeName);
        assertThat(retrievedCert).isEqualTo(testCertificate);

        final Response response = responsePromise.get();
        assertThat(successHandler.hasBeenInteractedWith()).isTrue();
        assertThat(response.getStatus()).isEqualTo(Status.OK);
    }

    private static X509Certificate getCertFromContext(Context context, String attributeName) {
        return (X509Certificate) context.asContext(AttributesContext.class).getAttributes().get(attributeName);
    }

    @Test
    void failsWhenCertificateRetrieverThrowsException() throws Exception {
        failsWhenCertificateRetrieverThrowsException(
                new AddCertificateToAttributesContextFilter(new ExceptionThrowingCertificateRetriever(), DEFAULT_CERTIFICATE_ATTRIBUTE),
                DEFAULT_CERTIFICATE_ATTRIBUTE);
    }

    private void failsWhenCertificateRetrieverThrowsException(AddCertificateToAttributesContextFilter filter, String attributeName) throws ExecutionException, InterruptedException, IOException {
        final TestSuccessResponseHandler successHandler = new TestSuccessResponseHandler();
        final Context context = createContext();
        final Promise<Response, NeverThrowsException> responsePromise = filter.filter(context, new Request(), successHandler);

        // No cert in attributes context
        assertThat(getCertFromContext(context, attributeName)).isNull();

        final Response response = responsePromise.get();
        assertThat(successHandler.hasBeenInteractedWith()).isFalse();
        assertThat(response.getStatus()).isEqualTo(Status.BAD_REQUEST);
        final JsonValue responseJson = json(response.getEntity().getJson());
        assertThat(responseJson.get("error_description").asString()).isEqualTo("Cert is invalid");
    }

    @Nested
    public class HeapletTests {
        private JsonValue filterConfig;
        private HeapImpl heap;

        @BeforeEach
        public void beforeEach() {
            filterConfig = json(object());
            heap = new HeapImpl(Name.of("test"));
        }

        private void setupCertRetrieverConfig() {
            heap.put("headerCertificateRetriever", new HeaderCertificateRetriever("clientCertHeader"));
            filterConfig.put("certificateRetriever", "headerCertificateRetriever");
        }

        @Test
        void failsWhenCertificateRetrieverIsNotConfigured() {
            final HeapException heapException = assertThrows(HeapException.class,
                    () -> new Heaplet().create(Name.of("test"), filterConfig, heap));
            assertThat(heapException.getMessage()).isEqualTo("Invalid object declaration");
            assertThat(heapException.getCause())
                    .isInstanceOf(JsonValueException.class).hasMessage("/certificateRetriever: Expecting a value");
        }

        @Test
        void testAddsCertWithDefaultAttributeName() throws Exception {
            setupCertRetrieverConfig();
            final AddCertificateToAttributesContextFilter filter = (AddCertificateToAttributesContextFilter) new Heaplet().create(Name.of("test"), filterConfig, heap);
            testCertificateIsAddedToAttributesContext(testCertificate, DEFAULT_CERTIFICATE_ATTRIBUTE, filter, createRequestWithCertHeader(testCertificate));
        }

        @Test
        void testAddsCertWithCustomAttributeName() throws Exception {
            setupCertRetrieverConfig();
            final String customCertAttributeName = "customCertAttributeName";
            filterConfig.add("certificateAttributeName", customCertAttributeName);
            final AddCertificateToAttributesContextFilter filter = (AddCertificateToAttributesContextFilter) new Heaplet().create(Name.of("test"), filterConfig, heap);
            testCertificateIsAddedToAttributesContext(testCertificate, customCertAttributeName, filter, createRequestWithCertHeader(testCertificate));
        }
    }

}