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

import static org.forgerock.json.JsonValue.field;
import static org.forgerock.json.JsonValue.json;
import static org.forgerock.json.JsonValue.object;
import static org.forgerock.openig.util.JsonValues.requiredHeapObject;

import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import org.forgerock.http.Filter;
import org.forgerock.http.Handler;
import org.forgerock.http.protocol.Request;
import org.forgerock.http.protocol.Response;
import org.forgerock.http.protocol.Status;
import org.forgerock.openig.fapi.mtls.CertificateRetriever;
import org.forgerock.openig.fapi.mtls.HeaderCertificateRetriever;
import org.forgerock.openig.heap.GenericHeaplet;
import org.forgerock.openig.heap.HeapException;
import org.forgerock.services.context.AttributesContext;
import org.forgerock.services.context.Context;
import org.forgerock.util.Reject;
import org.forgerock.util.promise.NeverThrowsException;
import org.forgerock.util.promise.Promise;
import org.forgerock.util.promise.Promises;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Filter which uses a configurable {@link CertificateRetriever} to retrieve a client's mTLS certificate and adds it
 * to the {@link AttributesContext} so that downstream filters can use it.
 */
public class AddCertificateToAttributesContextFilter implements Filter {

    public static final String DEFAULT_CERTIFICATE_ATTRIBUTE = "clientCertificate";

    private final Logger logger = LoggerFactory.getLogger(getClass());

    private final CertificateRetriever certificateRetriever;
    private final String attributeName;

    public AddCertificateToAttributesContextFilter(CertificateRetriever certificateRetriever, String attributeName) {
        this.certificateRetriever = Reject.checkNotNull(certificateRetriever, "certificateRetriever must be provided");
        this.attributeName = Reject.checkNotBlank(attributeName, "attributeName must be provided");
    }

    @Override
    public Promise<Response, NeverThrowsException> filter(Context context, Request request, Handler next) {
        try {
            final X509Certificate x509Certificate = certificateRetriever.retrieveCertificate(context, request);
            final AttributesContext attributesContext = context.asContext(AttributesContext.class);
            logger.debug("Adding transport cert to AttributesContext.{}", attributeName);
            attributesContext.getAttributes().put(attributeName, x509Certificate);
            return next.handle(context, request);
        } catch (CertificateException e) {
            logger.warn("Transport cert not valid", e);
            return Promises.newResultPromise(new Response(Status.BAD_REQUEST).setEntity(json(object(field("error_description", e.getMessage())))));
        }
    }

    /**
     * Heaplet used to create {@link AddCertificateToAttributesContextFilter} objects
     *
     * Mandatory fields:
     *  - certificateRetriever: {@link CertificateRetriever} object heap reference, this is used to retrieve the
     *                          certificate to store in the attributes context (see {@link HeaderCertificateRetriever})
     *
     *  Optional fields:
     *  - certificateAttributeName: the name of the attribute to store the certificate in, defaults to clientCertificate
     *
     * Example config:
     * {
     *           "comment": "Add the client's MTLS transport cert to the attributes context",
     *           "name": "AddCertificateToAttributesContextFilter",
     *           "type": "AddCertificateToAttributesContextFilter",
     *           "config": {
     *             "certificateRetriever": "HeaderCertificateRetriever"
     *           }
     * }
     */
    public static class Heaplet extends GenericHeaplet {
        @Override
        public Object create() throws HeapException {
            final CertificateRetriever certificateRetriever = config.get("certificateRetriever")
                                                                    .as(requiredHeapObject(heap, CertificateRetriever.class));
            final String attributeName = config.get("certificateAttributeName")
                                               .defaultTo(DEFAULT_CERTIFICATE_ATTRIBUTE).asString();

            return new AddCertificateToAttributesContextFilter(certificateRetriever, attributeName);
        }
    }
}
