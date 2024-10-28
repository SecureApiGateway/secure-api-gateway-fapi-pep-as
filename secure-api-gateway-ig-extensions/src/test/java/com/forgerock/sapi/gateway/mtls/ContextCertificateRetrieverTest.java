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
package com.forgerock.sapi.gateway.mtls;

import static com.forgerock.sapi.gateway.mtls.AddCertificateToAttributesContextFilter.DEFAULT_CERTIFICATE_ATTRIBUTE;
import static com.forgerock.sapi.gateway.util.CryptoUtils.generateRsaKeyPair;
import static com.forgerock.sapi.gateway.util.CryptoUtils.generateX509Cert;
import static org.assertj.core.api.Assertions.assertThat;
import static org.forgerock.json.JsonValue.json;
import static org.forgerock.json.JsonValue.object;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import org.forgerock.http.protocol.Request;
import org.forgerock.json.JsonValue;
import org.forgerock.openig.heap.Heap;
import org.forgerock.openig.heap.HeapImpl;
import org.forgerock.openig.heap.Name;
import org.forgerock.services.TransactionId;
import org.forgerock.services.context.AttributesContext;
import org.forgerock.services.context.RootContext;
import org.forgerock.services.context.TransactionIdContext;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import com.forgerock.sapi.gateway.mtls.ContextCertificateRetriever.Heaplet;

class ContextCertificateRetrieverTest {

    private static final Request EMPTY_REQUEST = new Request();

    @Test
    void shouldFetchCertFromContext() throws CertificateException {
        final String certificateAttribute = DEFAULT_CERTIFICATE_ATTRIBUTE;
        final ContextCertificateRetriever certificateRetriever = new ContextCertificateRetriever(certificateAttribute);
        testFetchCertFromContext(certificateAttribute, certificateRetriever);
    }

    private static void testFetchCertFromContext(String certificateAttribute, ContextCertificateRetriever certificateRetriever) throws CertificateException {
        final AttributesContext attributesContext = new AttributesContext(new RootContext());
        final X509Certificate certificate = generateX509Cert(generateRsaKeyPair(), "CN=blah");
        attributesContext.getAttributes().put(certificateAttribute, certificate);
        final TransactionIdContext context = new TransactionIdContext(attributesContext, new TransactionId("123"));

        assertThat(certificateRetriever.certificateExists(context, EMPTY_REQUEST)).isTrue();
        assertThat(certificateRetriever.retrieveCertificate(context, EMPTY_REQUEST)).isSameAs(certificate);
    }

    @Test
    void failsIfNoCertFound() {
        final ContextCertificateRetriever certificateRetriever = new ContextCertificateRetriever(DEFAULT_CERTIFICATE_ATTRIBUTE);
        testNoCertFound(certificateRetriever);
    }

    private static void testNoCertFound(ContextCertificateRetriever certificateRetriever) {
        final TransactionIdContext context = new TransactionIdContext(new AttributesContext(new RootContext()), new TransactionId("123"));
        assertThat(certificateRetriever.certificateExists(context, EMPTY_REQUEST)).isFalse();
        assertThrows(CertificateException.class, () -> certificateRetriever.retrieveCertificate(context, EMPTY_REQUEST));
    }

    @Nested
    public class HeapletTests {
        private JsonValue filterConfig;
        private Heap heap;

        @BeforeEach
        public void beforeEach() {
            filterConfig = json(object());
            heap = new HeapImpl(Name.of("test"));
        }

        @Test
        void shouldFetchCertFromDefaultAttributeName() throws Exception {
            ContextCertificateRetriever certificateRetriever = (ContextCertificateRetriever) new Heaplet().create(Name.of("test"), filterConfig, heap);
            testFetchCertFromContext(DEFAULT_CERTIFICATE_ATTRIBUTE, certificateRetriever);
        }

        @Test
        void shouldFetchCertFromCustomAttributeName() throws Exception {
            final String customCertAttribute = "customCertAttribute";
            filterConfig.add("certificateAttributeName", customCertAttribute);
            ContextCertificateRetriever certificateRetriever = (ContextCertificateRetriever) new Heaplet().create(Name.of("test"), filterConfig, heap);
            testFetchCertFromContext(customCertAttribute, certificateRetriever);
        }
    }

}