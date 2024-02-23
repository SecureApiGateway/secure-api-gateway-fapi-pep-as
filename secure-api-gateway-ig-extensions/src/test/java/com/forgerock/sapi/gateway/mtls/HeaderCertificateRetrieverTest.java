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

import static org.assertj.core.api.Assertions.assertThat;
import static org.forgerock.json.JsonValue.json;
import static org.forgerock.json.JsonValue.object;
import static org.junit.jupiter.api.Assertions.*;

import java.net.URLEncoder;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import org.forgerock.http.header.GenericHeader;
import org.forgerock.http.protocol.Request;
import org.forgerock.json.JsonValue;
import org.forgerock.json.JsonValueException;
import org.forgerock.openig.heap.Heap;
import org.forgerock.openig.heap.HeapException;
import org.forgerock.openig.heap.HeapImpl;
import org.forgerock.openig.heap.Name;
import org.forgerock.services.context.RootContext;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import com.forgerock.sapi.gateway.mtls.HeaderCertificateRetriever.Heaplet;
import com.forgerock.sapi.gateway.util.CryptoUtils;

class HeaderCertificateRetrieverTest {

    private static final String TEST_CERT_HEADER_NAME = "clientCertHeader";

    public static X509Certificate createValidCert() {
        return CryptoUtils.generateX509Cert(CryptoUtils.generateRsaKeyPair(), "CN=blah");
    }

    public static Request createRequestWithCertHeader(X509Certificate certificate) {
        return createRequestWithCertHeader(certificate, TEST_CERT_HEADER_NAME);
    }

    public static Request createRequestWithCertHeader(X509Certificate certificate, String headerName) {
        final Request request = new Request();
        final String certUrlEncodedPem = URLEncoder.encode(CryptoUtils.convertToPem(certificate), StandardCharsets.UTF_8);
        request.addHeaders(new GenericHeader(headerName, certUrlEncodedPem));
        return request;
    }

    @Test
    void successfullyRetrievesClientCert() throws Exception {
        testRetrievesClientCert(new HeaderCertificateRetriever(TEST_CERT_HEADER_NAME), TEST_CERT_HEADER_NAME);
    }

    private void testRetrievesClientCert(HeaderCertificateRetriever headerCertificateRetriever, String headerName) throws CertificateException {
        final X509Certificate clientCert = createValidCert();
        final Request request = createRequestWithCertHeader(clientCert, headerName);
        final X509Certificate actualCert = headerCertificateRetriever.retrieveCertificate(new RootContext("test"), request);
        assertEquals(clientCert, actualCert);
    }

    @Test
    void failsToRetrievesCertIfMissingHeader() {
        final HeaderCertificateRetriever headerCertificateRetriever = new HeaderCertificateRetriever(TEST_CERT_HEADER_NAME);
        final Request requestWithNoHeader = new Request();
        final CertificateException certificateException = assertThrows(CertificateException.class,
                () -> headerCertificateRetriever.retrieveCertificate(new RootContext("test"), requestWithNoHeader));

        assertEquals("Client mTLS certificate not provided", certificateException.getMessage());
    }

    @Test
    void failsToRetrievesCertIfHeaderNotValidUrlEncodedString() {
        final HeaderCertificateRetriever headerCertificateRetriever = new HeaderCertificateRetriever(TEST_CERT_HEADER_NAME);
        final Request requestWithNoHeader = new Request();
        final String headerValueInvalidUrlEncoding = "%-128blah blah blah";
        requestWithNoHeader.addHeaders(new GenericHeader(TEST_CERT_HEADER_NAME, headerValueInvalidUrlEncoding));
        final CertificateException certificateException = assertThrows(CertificateException.class,
                () -> headerCertificateRetriever.retrieveCertificate(new RootContext("test"), requestWithNoHeader));

        assertEquals("Failed to URL decode certificate header value. Expect certificate in PEM encoded then URL encoded format",
                certificateException.getMessage());
    }

    @Test
    void failsToRetrievesCertIfHeaderNotValidPemEncodedString() {
        final HeaderCertificateRetriever headerCertificateRetriever = new HeaderCertificateRetriever(TEST_CERT_HEADER_NAME);
        final Request requestWithNoHeader = new Request();
        final String headerValueInvalidPem = URLEncoder.encode("blah blah blah", Charset.defaultCharset());
        requestWithNoHeader.addHeaders(new GenericHeader(TEST_CERT_HEADER_NAME, headerValueInvalidPem));
        final CertificateException certificateException = assertThrows(CertificateException.class,
                () -> headerCertificateRetriever.retrieveCertificate(new RootContext("test"), requestWithNoHeader));

        assertEquals("Could not parse certificate: java.io.IOException: Empty input", certificateException.getMessage());
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
        void failsToCreateIfCertHeaderIsMissing() {
            final JsonValueException jsonValueException = assertThrows(JsonValueException.class,
                    () -> new Heaplet().create(Name.of("test"), filterConfig, heap));
            assertThat(jsonValueException.getMessage()).isEqualTo("/certificateHeaderName: Expecting a value");
        }

        @Test
        void testCreatingFilterWithAllConfig() throws HeapException, CertificateException {
            final String certHeader = "header123";
            filterConfig.add("certificateHeaderName", certHeader);
            final HeaderCertificateRetriever filter = (HeaderCertificateRetriever) new Heaplet().create(Name.of("test"), filterConfig, heap);
            testRetrievesClientCert(filter, certHeader);
        }
    }
}
