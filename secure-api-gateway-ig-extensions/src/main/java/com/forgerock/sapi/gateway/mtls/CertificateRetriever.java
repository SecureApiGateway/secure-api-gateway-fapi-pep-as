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

import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import org.forgerock.http.protocol.Request;
import org.forgerock.services.context.Context;

/**
 * Retriever of client mTLS certificates
 */
public interface CertificateRetriever {

    /**
     * Retrieves the client's mTLS certificate from the Request and Context
     *
     * @param context Context - the filter context
     * @param request Request - the HTTP request
     * @return X509Certificate supplied by the client as part of mTLS
     * @throws CertificateException thrown if the certificate could not be retrieved, or if the retrieved certificate
     * is malformed.
     */
    X509Certificate retrieveCertificate(Context context, Request request) throws CertificateException;

}
