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

import java.io.ByteArrayInputStream;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import org.forgerock.http.protocol.Request;
import org.forgerock.openig.heap.GenericHeaplet;
import org.forgerock.openig.heap.HeapException;
import org.forgerock.services.context.Context;
import org.forgerock.util.Reject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * CertificateRetriever implementation that retrieves the client's mTLS certificate from a HTTP Request Header.
 * <p>
 * The certificateHeaderName field determines which header the cert is retrieved from.
 * The header value is expected to be a PEM encoded then URL encoded X509 certificate.
 */
public class HeaderCertificateRetriever implements CertificateRetriever {

    private final Logger logger = LoggerFactory.getLogger(getClass());

    private final String certificateHeaderName;

    public HeaderCertificateRetriever(String certificateHeaderName) {
        Reject.ifBlank(certificateHeaderName, "certificateHeaderName must be provided");
        this.certificateHeaderName = certificateHeaderName;
    }

    @Override
    public X509Certificate retrieveCertificate(Context context, Request request) throws CertificateException {
        final String headerValue = retrieveCertificateHeader(request);
        if (headerValue == null) {
            logger.debug("No client cert could be found for header: {}", certificateHeaderName);
            throw new CertificateException("Client mTLS certificate not provided");
        }
        final String certPem;
        try {
             certPem = URLDecoder.decode(headerValue, StandardCharsets.UTF_8);
        } catch (RuntimeException ex) {
            logger.debug("Failed to URL decode cert from header: " + certificateHeaderName, ex);
            throw new CertificateException("Failed to URL decode certificate header value. " +
                    "Expect certificate in PEM encoded then URL encoded format", ex);
        }
        logger.debug("Found client cert: {}", certPem);
        return parseCertificate(certPem);
    }

    private String retrieveCertificateHeader(Request request) {
        return request.getHeaders().getFirst(certificateHeaderName);
    }

    @Override
    public boolean certificateExists(Context context, Request request) {
        return retrieveCertificateHeader(request) != null;
    }

    static X509Certificate parseCertificate(String cert) throws CertificateException {
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        Certificate certificate = cf.generateCertificate(new ByteArrayInputStream(cert.getBytes(StandardCharsets.UTF_8)));
        if (!(certificate instanceof X509Certificate)) {
            throw new CertificateException("client tls cert must be in X.509 format");
        }
        return (X509Certificate) certificate;
    }

    /**
     * Heaplet responsible for creating {@link HeaderCertificateRetriever} objects
     * <p>
     * Required config:
     * - clientTlsCertHeader String the name of the header which contains the certificate
     * <p>
     * Example config:
     * {
     *       "name": "HeaderCertificateRetriever",
     *       "type": "HeaderCertificateRetriever",
     *       "config": {
     *         "certificateHeaderName": "ssl-client-cert"
     *       }
     * }
     */
    public static class Heaplet extends GenericHeaplet {
        @Override
        public Object create() throws HeapException {
            return new HeaderCertificateRetriever(config.get("certificateHeaderName").required().asString());
        }
    }
}
