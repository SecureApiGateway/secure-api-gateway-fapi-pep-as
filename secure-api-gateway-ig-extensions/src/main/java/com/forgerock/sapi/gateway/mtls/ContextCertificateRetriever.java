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

import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Optional;

import org.forgerock.http.protocol.Request;
import org.forgerock.openig.heap.GenericHeaplet;
import org.forgerock.openig.heap.HeapException;
import org.forgerock.services.context.Context;
import org.forgerock.util.Reject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.forgerock.sapi.gateway.util.ContextUtils;

/**
 * CertificateRetriever implementation which retrieves the certificate from the {@link org.forgerock.services.context.AttributesContext}.
 * <p>
 * This retriever must only run after the {@link AddCertificateToAttributesContextFilter} has installed the certificate
 * into the context.
 */
public class ContextCertificateRetriever implements CertificateRetriever {

    private final Logger logger = LoggerFactory.getLogger(getClass());

    private final String certificateAttribute;

    public ContextCertificateRetriever(String certificateAttribute) {
        this.certificateAttribute = Reject.checkNotBlank(certificateAttribute, "certificateAttribute must be provided");
    }

    @Override
    public X509Certificate retrieveCertificate(Context context, Request request) throws CertificateException {
        final Optional<X509Certificate> certificate = getCertificateAttribute(context);
        return certificate.orElseThrow(() -> {
            logger.debug("No client cert could be found in attribute: {}", certificateAttribute);
            return new CertificateException("Client mTLS certificate not provided");
        });
    }

    private Optional<X509Certificate> getCertificateAttribute(Context context) {
        return ContextUtils.getAttributeAsType(context, certificateAttribute, X509Certificate.class);
    }

    @Override
    public boolean certificateExists(Context context, Request request) {
        return getCertificateAttribute(context).isPresent();
    }

    /**
     * Heaplet responsible for creating {@link ContextCertificateRetriever} objects
     * <p>
     * Optional fields:
     * - certificateAttributeName String the name of the attribute to retrieve the certificate from, defaults to clientCertificate
     * <p>
     * Example config:
     * {
     *       "name": "ContextCertificateRetriever",
     *       "type": "ContextCertificateRetriever",
     *       "config": {
     *         "certificateAttributeName": "clientCertificate"
     *       }
     * }
     */
    public static class Heaplet extends GenericHeaplet {
        @Override
        public Object create() throws HeapException {
            return new ContextCertificateRetriever(config.get("certificateAttributeName")
                                                         .defaultTo(DEFAULT_CERTIFICATE_ATTRIBUTE).asString());
        }
    }
}
