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
/**
 * Provides an extensible framework to address a solution when a specification require sign messages as JSON Web Signatures (JWS) to met Non-repudiation requirements,
 * JSON Web Signature (JWS) represents the payload of a JWS as a base64url-encoded value and uses this value in the JWS Signature computation.<br/><br/>
 * JSON Web Signature spec
 * <ul>
 *     <li><a href='https://datatracker.ietf.org/doc/html/rfc7515'>RFC7515 JSON Web Signature (JWS)</a></li>
 *     <li><a href='https://datatracker.ietf.org/doc/html/rfc7159'>RFC7159 JSON-Based data structures</a></li>
 * </ul>
 * Reading recommendations
 * <ul>
 *     <li><a href='https://community.forgerock.com/t/identity-gateway-7-0-async-programming-101/29'>Identity Gateway async programming</a></li>
 *     <li><a href='https://community.forgerock.com/t/identity-gateway-7-1-highway-to-async-programming/28'>Identity Gateway highway to async programming</a></li>
 * </ul>
 * <h2>Package Specification</h2>
 * <p>
 * Provides:
 * <ul>
 *     <li>A signer interface {@link com.forgerock.sapi.gateway.jws.signer.JwsSigner} to abstract the signature methods</li>
 *     <li>Compact Serialization, as a signer implementation {@link com.forgerock.sapi.gateway.jws.signer.CompactSerializationJwsSigner}</li>
 *     <li>Singer Exception type {@link com.forgerock.sapi.gateway.jws.signer.JwsSignerException} throw by the sign task of an implemented signer if it fails</li>
 * </ul>
 * @author	  Jorge Sanchez Perez
 * @since	  2.0
 */
package com.forgerock.sapi.gateway.jws.signer;